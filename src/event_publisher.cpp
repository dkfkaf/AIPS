#include "miniips/event_publisher.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <variant>

namespace miniips {
namespace {
using Json = nlohmann::json;

template <typename Factory>
void emit(EventLogger& logger, const Factory& factory) noexcept {
    if (logger.failed()) {
        logger.reject_event();
        return;
    }
    try {
        logger.write(factory());
    } catch (...) {
        logger.reject_event();
    }
}
Event event(EventType type, EventAction action, const EventContext& context, Json fields) {
    Event result;
    result.type = type;
    result.action = action;
    result.context = context;
    result.fields = std::move(fields);
    return result;
}
Json issues(const ReassemblyIssues& value) {
    auto result = Json::array();
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i]) result.push_back(reassembly_issue_name(static_cast<ReassemblyIssue>(i)));
    }
    return result;
}
Json stream_fields(const StreamSummary& stream) {
    return {{"direction", stream.direction == FlowDirection::Forward ? "fwd" : "bwd"},
            {"bytes", stream.bytes},
            {"new_bytes", stream.new_bytes},
            {"pending_bytes", stream.pending_bytes},
            {"fin_seen", stream.fin_seen},
            {"closed", stream.closed},
            {"issues", issues(stream.issues)}};
}
Json direction_fields(const FlowDirectionStats& stats) {
    return {{"packets", stats.packets},       {"bytes", stats.bytes},
            {"iat_sum_us", stats.iat_sum_us}, {"iat_samples", stats.iat_samples},
            {"syn", stats.syn_count},         {"ack", stats.ack_count},
            {"fin", stats.fin_count},         {"rst", stats.rst_count},
            {"psh", stats.psh_count}};
}
std::string_view tcp_state(TcpFlowState state) {
    switch (state) {
        case TcpFlowState::Observed:
            return "observed";
        case TcpFlowState::SynSeen:
            return "syn_seen";
        case TcpFlowState::Established:
            return "established";
        case TcpFlowState::Closing:
            return "closing";
        case TcpFlowState::Closed:
            return "closed";
        case TcpFlowState::Reset:
            return "reset";
    }
    return "unknown";
}
EventContext flow_context(const FlowSnapshot& flow, std::optional<std::chrono::microseconds> at,
                          CaptureMode mode) {
    EventContext context;
    context.captured_at = at;
    context.mode = mode;
    context.flow_id = flow.flow_id;
    context.source = flow.first_source;
    context.destination = flow.first_source == flow.key.low ? flow.key.high : flow.key.low;
    context.protocol = flow.key.protocol;
    return context;
}
Json flow_fields(const FlowSnapshot& flow, std::string_view reason) {
    return {{"reason", reason},
            {"first_seen_us", flow.first_seen.count()},
            {"last_seen_us", flow.last_seen.count()},
            {"fwd", direction_fields(flow.fwd)},
            {"bwd", direction_fields(flow.bwd)},
            {"tcp_state", flow.tcp_state ? Json(tcp_state(*flow.tcp_state)) : Json(nullptr)}};
}
void warning(EventLogger& logger, const EventContext& context, const StreamSummary& stream,
             std::string_view reason, bool resolved = false) noexcept {
    emit(logger, [&] {
        auto fields = stream_fields(stream);
        // Common direction is reserved and supplied by the context.
        fields.erase("direction");
        fields["reason"] = reason;
        fields["severity"] = resolved ? "info" : "warning";
        fields["resolved"] = resolved;
        return event(EventType::ReassemblyWarning, EventAction::Observe, context,
                     std::move(fields));
    });
}
void end_flow(EventLogger& logger, const FlowEnd& ended,
              std::optional<std::chrono::microseconds> watermark, CaptureMode mode) noexcept {
    const auto context = flow_context(ended.flow, watermark, mode);
    for (const auto& stream : ended.streams) {
        if (stream && stream->issues.any()) {
            auto oriented = context;
            oriented.direction = stream->direction;
            if (stream->direction == FlowDirection::Backward) {
                std::swap(oriented.source, oriented.destination);
            }
            warning(logger, oriented, *stream, "final_incomplete");
        }
    }
    emit(logger, [&] {
        const auto reason = ended.reason == FlowEndReason::Expired   ? "expired"
                            : ended.reason == FlowEndReason::Eof     ? "eof"
                            : ended.reason == FlowEndReason::Stopped ? "stopped"
                                                                     : "aborted";
        auto fields = flow_fields(ended.flow, reason);
        fields["reassembly"] = Json::array();
        for (const auto& stream : ended.streams) {
            if (stream) fields["reassembly"].push_back(stream_fields(*stream));
        }
        return event(EventType::Flow, EventAction::Observe, context, std::move(fields));
    });
}
EventContext packet_context(const PacketResult& result, CaptureMode mode) {
    EventContext context;
    context.captured_at = result.captured_at;
    context.mode = mode;
    context.packet_number = result.packet_number;
    if (result.packet) {
        const auto& packet = *result.packet;
        context.source = FlowEndpoint{packet.src_ip, packet.src_port};
        context.destination = FlowEndpoint{packet.dst_ip, packet.dst_port};
        context.protocol = packet.protocol;
    }
    if (result.flow) {
        if (const auto* flow = std::get_if<FlowObservation>(&*result.flow)) {
            context.flow_id = flow->flow.flow_id;
            context.direction = flow->direction;
        }
    }
    return context;
}
}  // namespace

void publish_error(EventLogger& logger, const EventContext& context, ErrorInfo error) noexcept {
    emit(logger, [&] {
        auto result = event(EventType::EngineError, EventAction::Error, context,
                            {{"error_domain", error.domain}, {"reason", error.reason}});
        result.message.assign(error.message.substr(0, 4096));
        result.message_truncated = error.message.size() > 4096;
        return result;
    });
}

void publish_packet(EventLogger& logger, const PacketResult& result,
                    const RunPublication& run) noexcept {
    for (const auto& ended : result.expired) end_flow(logger, ended, result.watermark, run.mode);
    const auto context = packet_context(result, run.mode);
    if (result.parse_error) {
        emit(logger, [&] {
            return event(EventType::ParseError, EventAction::Skip, context,
                         {{"reason", parse_error_name(*result.parse_error)},
                          {"captured_bytes", result.captured_bytes},
                          {"original_bytes", result.original_bytes}});
        });
        return;
    }
    if (result.flow) {
        if (const auto* flow = std::get_if<FlowObservation>(&*result.flow)) {
            if (flow->created)
                emit(logger, [&] {
                    return event(EventType::Flow, EventAction::Observe,
                                 flow_context(flow->flow, result.captured_at, run.mode),
                                 flow_fields(flow->flow, "created"));
                });
        } else {
            publish_error(logger, context,
                          {"flow", "capacity_exceeded", "Flow capacity exceeded."});
        }
    }
    if (result.reassembly) {
        const auto& stream = *result.reassembly;
        for (std::size_t i = 0; i < stream.events.size(); ++i) {
            if (stream.events[i]) {
                const auto issue = static_cast<ReassemblyIssue>(i);
                warning(logger, context, stream, reassembly_issue_name(issue),
                        issue == ReassemblyIssue::GapFilled);
            }
        }
    }
    if (result.processing_error) {
        const auto& error = *result.processing_error;
        publish_error(logger, context, {error.domain, error.reason, error.message});
        return;
    }
    if (!result.packet) return;
    if (result.decision) {
        for (const auto& match : result.decision->matches) {
            if (match.action == RuleAction::Pass) continue;
            emit(logger, [&] {
                auto row =
                    event(EventType::Alert,
                          match.action == RuleAction::Drop ? EventAction::Drop : EventAction::Alert,
                          context,
                          {{"scope", match.scope == RuleScope::Packet ? "packet" : "stream"},
                           {"match_end", match.end_offset}});
                row.sid = match.sid;
                row.message = match.message;
                return row;
            });
        }
    }
    if (run.mode == CaptureMode::Inline) return;
    emit(logger, [&] {
        const auto* decision = result.decision ? &*result.decision : nullptr;
        const bool drop = decision && decision->action == DetectionAction::Drop;
        auto row = event(
            EventType::Verdict, drop ? EventAction::Drop : EventAction::Allow, context,
            {{"reason", result.rules_enabled ? "rules" : "no_rules"},
             {"rules_enabled", result.rules_enabled},
             {"matched_action",
              decision && decision->terminal_sid ? Json(drop ? "drop" : "pass") : Json(nullptr)},
             {"rule_matches_emitted", decision ? decision->matches.size() : 0},
             {"rule_matches_suppressed", decision ? decision->suppressed : 0},
             {"stream_window_available", decision && decision->stream_evaluated},
             {"stream_scope", result.reassembly                                   ? "bounded_prefix"
                              : result.packet->protocol == TransportProtocol::Tcp ? "untracked"
                                                                                  : "not_tcp"},
             {"stream_issues",
              result.reassembly ? issues(result.reassembly->issues) : Json::array()}});
        if (decision) row.sid = decision->terminal_sid;
        return row;
    });
}

void publish_finish(EventLogger& logger, const FinishResult& result,
                    const RunPublication& run) noexcept {
    for (const auto& flow : result.flows) end_flow(logger, flow, result.stats.watermark, run.mode);
    emit(logger, [&] {
        const auto& stats = result.stats;
        const auto logs = logger.stats();
        EventContext context;
        context.captured_at = stats.watermark;
        context.mode = run.mode;
        auto row =
            event(EventType::Stats, EventAction::None, context,
                  {{"packets_total", stats.packets},
                   {"packets_parsed", stats.parsed},
                   {"packets_skipped", stats.skipped},
                   {"processing_errors", stats.processing_errors},
                   {"flows_created", stats.flow.created},
                   {"flows_expired", stats.flow.expired},
                   {"flows_active_at_finish", stats.flow.active},
                   {"flows_rejected", stats.flow.rejected},
                   {"reassembly_bytes_emitted", stats.tcp.bytes_emitted},
                   {"reassembly_overlap_conflicts", stats.tcp.overlap_conflicts},
                   {"reassembly_rejected", stats.tcp.rejected},
                   {"incomplete_directions", stats.incomplete_directions},
                   {"tcp_memory_bytes", stats.tcp.memory_bytes},
                   {"tcp_peak_memory_bytes", stats.tcp.peak_memory_bytes},
                   {"rule_state_bytes", stats.rules.state_bytes},
                   {"rule_peak_state_bytes", stats.rules.peak_state_bytes},
                   {"rules_enabled", stats.rules_enabled},
                   {"rule_packets_evaluated", stats.rules.packets_evaluated},
                   {"rule_matches_emitted", stats.rules.events_emitted},
                   {"rule_matches_suppressed", stats.rules.suppressed},
                   {"rule_matches_total", stats.rules.events_emitted + stats.rules.suppressed},
                   {"detections", stats.detections},
                   {"simulated_drop_packets", stats.rules.drops},
                   {"actual_drop_packets", 0},
                   {"capture_complete", stats.capture_complete},
                   {"log_status_at_emit", "ok"},
                   {"log_events_attempted", logs.attempted + 1},
                   {"log_events_written", logs.written + 1},
                   {"log_events_failed", logs.failed_events},
                   {"log_events_dropped", logs.dropped},
                   {"log_io_errors", logs.io_errors},
                   {"alert_events_written", logs.alert_written}});
        if (run.mode == CaptureMode::Live) {
            const auto* capture = run.capture ? &*run.capture : nullptr;
            row.fields["interface"] = run.interface;
            row.fields["run_complete"] = run.run_complete;
            row.fields["stop_reason"] = run.stop_reason;
            row.fields["capture_stats"] = {
                {"status",
                 capture ? (capture->available ? "available" : "unavailable") : "not_open"},
                {"ps_recv",
                 capture && capture->available ? Json(capture->received) : Json(nullptr)},
                {"ps_drop", capture && capture->available ? Json(capture->dropped) : Json(nullptr)},
                {"ps_ifdrop",
                 capture && capture->available ? Json(capture->interface_dropped) : Json(nullptr)},
                {"ifdrop_availability", "platform_dependent"},
                {"counter_bits", capture ? Json(capture->counter_bits) : Json(nullptr)},
                {"sample", "before_close"},
                {"error", capture ? capture->error.substr(0, 4096) : ""}};
        }
        if (run.mode == CaptureMode::Inline) {
            const auto counters = run.queue.value_or(QueueStats{});
            row.fields["queue_num"] = run.queue_num;
            row.fields["run_complete"] = run.run_complete;
            row.fields["stop_reason"] = run.stop_reason;
            row.fields["simulated_drop_packets"] = 0;
            row.fields["logical_rule_drop_packets"] = stats.rules.drops;
            row.fields["actual_drop_packets"] = counters.dropped;
            row.fields["actual_accept_packets"] = counters.accepted;
            row.fields["fallback_drop_packets"] = counters.fallback_drops;
            row.fields["queue_stats"] = {{"callbacks", counters.callbacks},
                                         {"valid_ids", counters.valid_ids},
                                         {"attempts", counters.attempts},
                                         {"accepted", counters.accepted},
                                         {"dropped", counters.dropped},
                                         {"failed", counters.failed},
                                         {"missing_ids", counters.missing_ids},
                                         {"processing_errors", counters.processing_errors},
                                         {"receive_errors", counters.receive_errors},
                                         {"overflow_errors", counters.overflow_errors},
                                         {"close_errors", counters.close_errors}};
        }
        return row;
    });
}

void publish_inline_verdict(EventLogger& logger, const PacketResult* result,
                            const InlineReceipt& receipt, const RunPublication& run) noexcept {
    emit(logger, [&] {
        auto context = result ? packet_context(*result, CaptureMode::Inline) : EventContext{};
        context.mode = CaptureMode::Inline;
        context.captured_at = receipt.received_at;
        context.enforced = receipt.attempted && receipt.sent;
        const auto* decision = result && result->decision ? &*result->decision : nullptr;
        const bool limited =
            result && ((result->flow && std::holds_alternative<FlowError>(*result->flow)) ||
                       (result->reassembly && result->reassembly->issues.any()));
        const auto status = receipt.fallback                ? "error"
                            : result && result->parse_error ? "unsupported"
                            : !result                       ? "unknown"
                            : limited                       ? "limited"
                                                            : "parsed";
        const auto reason =
            !receipt.sent ? "verdict_send_failed"
            : receipt.reason == VerdictReason::Decision && result && !result->rules_enabled
                ? "no_rules"
                : verdict_reason_name(receipt.reason);
        auto row = event(
            EventType::Verdict,
            receipt.action == QueueAction::Drop ? EventAction::Drop : EventAction::Allow, context,
            {{"queue_num", run.queue_num},
             {"queue_packet_id", receipt.id},
             {"queue_delivery_number", receipt.delivery_number},
             {"verdict_attempted", receipt.attempted},
             {"verdict_sent", receipt.sent},
             {"fallback", receipt.fallback},
             {"reason", reason},
             {"inspection_status", status},
             {"rules_enabled", result ? Json(result->rules_enabled) : Json(nullptr)},
             {"rule_matches_emitted", decision ? decision->matches.size() : 0},
             {"rule_matches_suppressed", decision ? decision->suppressed : 0},
             {"stream_window_available", decision && decision->stream_evaluated}});
        if (decision && !receipt.fallback) row.sid = decision->terminal_sid;
        return row;
    });
}
}  // namespace miniips
