#include "miniips/engine.hpp"

#include <algorithm>
#include <cstddef>
#include <stdexcept>
#include <utility>
#include <variant>

namespace miniips {
namespace {

PacketMetadata metadata(const ParsedPacket& packet) {
    return {packet.captured_at,
            packet.src_ip,
            packet.dst_ip,
            packet.src_port,
            packet.dst_port,
            packet.ip_total_length,
            packet.ip_header_bytes,
            packet.transport_header_bytes,
            packet.payload.size(),
            packet.protocol,
            packet.tcp};
}

StreamSummary summarize(const ReassemblyUpdate& update) {
    return {update.flow_id,
            update.direction,
            update.contiguous_prefix.size(),
            update.newly_contiguous.size(),
            update.pending_bytes,
            update.issues,
            update.events,
            update.fin_seen,
            update.closed,
            update.end};
}

void sort_flows(std::vector<FlowEnd>& records) {
    std::sort(records.begin(), records.end(), [](const FlowEnd& lhs, const FlowEnd& rhs) {
        return lhs.flow.flow_id < rhs.flow.flow_id;
    });
}

}  // namespace

Engine::Engine(EngineConfig config, std::optional<RuleSet> rules)
    : flows_(config.flows),
      reassembler_({.stream_bytes = config.tcp_stream_bytes,
                    .memory_bytes = config.tcp_memory_bytes,
                    .max_flows = config.flows.max_entries}) {
    if (config.rule_state_bytes == 0) {
        throw std::invalid_argument("Rule state memory limit must be positive.");
    }
    if (rules) {
        detector_.emplace(std::move(*rules),
                          RuleEngineConfig{config.flows.max_entries, config.rule_state_bytes});
    }
}

void Engine::collect_end(const FlowSnapshot& flow, FlowEndReason reason,
                         std::vector<FlowEnd>& records) {
    records.push_back({flow, reason, {}});
    auto& ended = records.back();
    if (detector_) {
        detector_->forget_flow(flow.flow_id);
    }
    reassembler_.finish_flow(
        flow.flow_id,
        reason == FlowEndReason::Expired ? ReassemblyEnd::IdleTimeout : ReassemblyEnd::CaptureEnd,
        [&](const ReassemblyUpdate& update) {
            ended.streams[update.direction == FlowDirection::Forward ? 0U : 1U] = summarize(update);
            counters_.incomplete_directions += update.issues.any() ? 1U : 0U;
        });
}

PacketResult Engine::inspect(const PacketEnvelope& envelope) {
    if (finished_ || processing_failed_) {
        throw std::logic_error("Cannot inspect after finish or a fatal processing error.");
    }
    if (envelope.captured_at.count() < 0) {
        throw std::invalid_argument("Capture timestamp must be nonnegative.");
    }
    PacketResult result;
    result.packet_number = ++counters_.packets;
    result.captured_at = envelope.captured_at;
    result.captured_bytes = envelope.bytes.size();
    result.original_bytes = envelope.original_length;
    result.rules_enabled = detector_.has_value();
    result.watermark = counters_.watermark ? std::max(*counters_.watermark, envelope.captured_at)
                                           : envelope.captured_at;
    counters_.watermark = result.watermark;
    const auto expire = [&](const FlowSnapshot& old) {
        collect_end(old, FlowEndReason::Expired, result.expired);
    };
    const auto parsed = parse_packet(envelope);
    if (const auto* packet = std::get_if<ParsedPacket>(&parsed)) {
        ++counters_.parsed;
        result.packet = metadata(*packet);
        result.flow = flows_.observe(*packet, expire);
        std::optional<ReassemblyUpdate> stream;
        if (packet->protocol == TransportProtocol::Tcp) {
            if (const auto* flow = std::get_if<FlowObservation>(&*result.flow)) {
                stream = reassembler_.observe(*flow, *packet);
                result.reassembly = summarize(*stream);
            }
        }
        if (detector_) {
            try {
                auto decision =
                    detector_->evaluate(*packet, std::get_if<FlowObservation>(&*result.flow),
                                        stream ? &*stream : nullptr);
                for (const auto& match : decision.matches) {
                    counters_.detections += match.action != RuleAction::Pass ? 1U : 0U;
                }
                result.decision = std::move(decision);
            } catch (const DetectionError& error) {
                result.processing_error = ProcessingError{"detection", "state_limit", error.what()};
                ++counters_.processing_errors;
                processing_failed_ = true;
            }
        }
    } else {
        ++counters_.skipped;
        result.parse_error = std::get<ParseError>(parsed);
        flows_.expire(envelope.captured_at, expire);
    }
    sort_flows(result.expired);
    return result;
}

FinishResult Engine::finish(EngineEnd reason) {
    if (reason != EngineEnd::Eof && reason != EngineEnd::Aborted && reason != EngineEnd::Stopped) {
        throw std::invalid_argument("Unknown engine end reason.");
    }
    FinishResult result;
    if (!finished_) {
        end_reason_ = processing_failed_ ? EngineEnd::Aborted : reason;
        flows_.visit([&](const FlowSnapshot& flow) {
            collect_end(flow,
                        end_reason_ == EngineEnd::Eof       ? FlowEndReason::Eof
                        : end_reason_ == EngineEnd::Stopped ? FlowEndReason::Stopped
                                                            : FlowEndReason::Aborted,
                        result.flows);
        });
        if (detector_) {
            detector_->clear();
        }
        sort_flows(result.flows);
        finished_ = true;
        counters_.capture_complete = end_reason_ == EngineEnd::Eof;
    }
    result.reason = end_reason_;
    result.stats = stats();
    return result;
}

EngineStats Engine::stats() const noexcept {
    auto result = counters_;
    result.flow = flows_.stats();
    result.tcp = reassembler_.stats();
    result.rules_enabled = detector_.has_value();
    if (detector_) {
        result.rules = detector_->stats();
    }
    return result;
}

}  // namespace miniips
