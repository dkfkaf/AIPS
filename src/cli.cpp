#include "miniips/cli.hpp"

#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <filesystem>
#include <limits>
#include <nlohmann/json.hpp>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <variant>

#include "miniips/capture_source.hpp"
#include "miniips/event_publisher.hpp"
#include "miniips/flow_table.hpp"
#include "miniips/live_pcap_source.hpp"
#include "miniips/packet_parser.hpp"
#include "miniips/rule_engine.hpp"
#include "miniips/rule_loader.hpp"
#include "miniips/tcp_reassembler.hpp"

namespace miniips {
namespace {

constexpr std::string_view HELP_TEXT =
    "Usage: miniips --help | --version\n"
    "       miniips --mode pcap --input <file.pcap>\n"
    "       miniips --mode live --interface <name>\n"
    "\n"
    "Options:\n"
    "  --help       Show this help message.\n"
    "  --version    Show the program version.\n"
    "  --mode pcap  Analyze an offline Ethernet IPv4 TCP/UDP capture.\n"
    "  --mode live  Inspect an Ethernet interface without blocking traffic.\n"
    "  --interface NAME Select the live capture interface.\n"
    "  --packet-count N Stop live capture after N frames (optional).\n"
    "  --input PATH Read packets from this capture file.\n"
    "  --max-flows N Limit active flows (default: 10000).\n"
    "  --flow-idle-timeout-seconds N Expire idle flows (default: 120).\n"
    "  --tcp-stream-bytes N Limit each TCP prefix/depth (default: 65536).\n"
    "  --tcp-memory-bytes N Limit TCP payload arrays + bitmaps (default: 134217728).\n"
    "  --rules PATH Load and apply validated JSON rules (optional).\n"
    "  --log PATH  Create a new JSONL file; '-' selects JSONL-only stdout.\n"
    "  --rule-state-bytes N Limit stream-rule watermark arrays (default: 33554432).\n"
    "\n"
    "A6: PCAP/live decisions are simulated (enforced=false); inline is unavailable.\n"
    "Memory limit covers arrays, not total process RSS. Incomplete streams are reported.\n";

constexpr std::int64_t MICROSECONDS_PER_SECOND = 1000000;

std::optional<std::uint64_t> positive_integer(std::string_view text) {
    if (text.empty()) {
        return std::nullopt;
    }
    std::uint64_t value = 0;
    const auto result = std::from_chars(text.data(), text.data() + text.size(), value);
    if (result.ec != std::errc{} || result.ptr != text.data() + text.size() || value == 0) {
        return std::nullopt;
    }
    return value;
}

std::string ipv4_text(std::uint32_t address) {
    return std::to_string((address >> 24U) & 0xFFU) + "." +
           std::to_string((address >> 16U) & 0xFFU) + "." +
           std::to_string((address >> 8U) & 0xFFU) + "." + std::to_string(address & 0xFFU);
}

void print_issues(const ReassemblyIssues& issues, std::ostream& output) {
    bool first = true;
    for (std::size_t index = 0; index < issues.size(); ++index) {
        if (issues[index]) {
            if (!first) {
                output << ',';
            }
            output << reassembly_issue_name(static_cast<ReassemblyIssue>(index));
            first = false;
        }
    }
    if (first) {
        output << "none";
    }
}

void print_stream_fields(const StreamSummary& update, std::ostream& output) {
    output << " stream_bytes=" << update.bytes << " stream_new_bytes=" << update.new_bytes
           << " stream_pending_bytes=" << update.pending_bytes
           << " stream_closed=" << (update.closed ? 1 : 0) << " issues=";
    print_issues(update.issues, output);
}

void print_reassembly_event(const StreamSummary& update, std::ostream& output) {
    const auto direction = update.direction == FlowDirection::Forward ? "fwd" : "bwd";
    if (update.end) {
        output << "reassembly_end flow_id=" << update.flow_id << " direction=" << direction
               << " reason="
               << (*update.end == ReassemblyEnd::IdleTimeout ? "idle_timeout" : "capture_end");
        print_stream_fields(update, output);
        output << '\n';
    } else {
        for (std::size_t index = 0; index < update.events.size(); ++index) {
            if (update.events[index]) {
                output << "reassembly_event flow_id=" << update.flow_id
                       << " direction=" << direction
                       << " reason=" << reassembly_issue_name(static_cast<ReassemblyIssue>(index));
                print_stream_fields(update, output);
                output << '\n';
            }
        }
    }
    if (!output) {
        throw std::runtime_error("Output stream failed.");
    }
}

void print_packet(std::uint64_t number, const PacketMetadata& packet, const FlowResult& result,
                  const std::optional<StreamSummary>& reassembly, std::ostream& output) {
    output << "packet=" << number << " timestamp_us=" << packet.captured_at.count()
           << " protocol=" << (packet.protocol == TransportProtocol::Tcp ? "tcp" : "udp")
           << " src_ip=" << ipv4_text(packet.src_ip) << " src_port=" << packet.src_port
           << " dst_ip=" << ipv4_text(packet.dst_ip) << " dst_port=" << packet.dst_port
           << " ip_bytes=" << packet.ip_total_length
           << " ip_header_bytes=" << packet.ip_header_bytes
           << " transport_header_bytes=" << packet.transport_header_bytes
           << " payload_bytes=" << packet.payload_bytes;
    if (packet.tcp) {
        output << " tcp_seq=" << packet.tcp->sequence_number
               << " tcp_ack=" << packet.tcp->acknowledgement_number
               << " tcp_flags=" << static_cast<unsigned int>(packet.tcp->flags);
    }
    if (const auto* observation = std::get_if<FlowObservation>(&result)) {
        const auto& flow = observation->flow;
        output << " flow_id=" << flow.flow_id << " direction="
               << (observation->direction == FlowDirection::Forward ? "fwd" : "bwd")
               << " fwd_packets=" << flow.fwd.packets << " bwd_packets=" << flow.bwd.packets
               << " fwd_bytes=" << flow.fwd.bytes << " bwd_bytes=" << flow.bwd.bytes;
    } else {
        output << " flow_id=untracked direction=unknown";
    }
    if (reassembly) {
        print_stream_fields(*reassembly, output);
    } else {
        output << " stream_status="
               << (packet.protocol == TransportProtocol::Tcp ? "untracked" : "not_tcp");
    }
    output << '\n';
}

std::string_view rule_action_name(RuleAction action) {
    if (action == RuleAction::Alert) {
        return "alert";
    }
    return action == RuleAction::Drop ? "drop" : "pass";
}

std::string encoded_message(const std::string& message) {
    // ASCII encoding protects Unicode separators/C1 as well as JSON C0 controls.
    const auto encoded = nlohmann::json(message).dump(-1, ' ', true);
    std::string result;
    result.reserve(encoded.size());
    for (const char byte : encoded) {
        if (byte == '\x7f') {
            result += "\\u007f";
        } else {
            result += byte;
        }
    }
    return result;
}

void print_decision(std::uint64_t packet_number, const FlowResult& flow,
                    const DetectionDecision& decision, std::ostream& output, CaptureMode mode) {
    const auto* observation = std::get_if<FlowObservation>(&flow);
    for (const auto& match : decision.matches) {
        output << "rule_match packet=" << packet_number << " flow_id=";
        if (observation) {
            output << observation->flow.flow_id;
        } else {
            output << "untracked";
        }
        output << " sid=" << match.sid << " action=" << rule_action_name(match.action)
               << " scope=" << (match.scope == RuleScope::Packet ? "packet" : "stream")
               << " match_end=" << match.end_offset << " message=" << encoded_message(match.message)
               << " mode=" << capture_mode_name(mode) << " enforced=false\n";
    }
    output << "decision packet=" << packet_number
           << " action=" << (decision.action == DetectionAction::Drop ? "drop" : "allow")
           << " terminal_sid=";
    if (decision.terminal_sid) {
        output << *decision.terminal_sid;
    } else {
        output << "none";
    }
    output << " emitted=" << decision.matches.size() << " suppressed=" << decision.suppressed
           << " stream_evaluated=" << (decision.stream_evaluated ? 1 : 0)
           << " mode=" << capture_mode_name(mode) << " enforced=false\n";
    if (!output) {
        throw std::runtime_error("Output stream failed.");
    }
}

void print_summary(const EngineStats& stats, std::ostream& output, CaptureMode mode) {
    output << (mode == CaptureMode::Pcap ? "pcap_summary packets=" : "live_summary packets=")
           << stats.packets << " parsed=" << stats.parsed << " skipped=" << stats.skipped << '\n';
    output << "flow_summary created=" << stats.flow.created << " active=" << stats.flow.active
           << " expired=" << stats.flow.expired << " rejected=" << stats.flow.rejected << '\n';
    output << "reassembly_summary bytes_emitted=" << stats.tcp.bytes_emitted
           << " overlap_conflicts=" << stats.tcp.overlap_conflicts
           << " rejected=" << stats.tcp.rejected << " active=" << stats.tcp.active_flows
           << " memory_bytes=" << stats.tcp.memory_bytes
           << " peak_memory_bytes=" << stats.tcp.peak_memory_bytes << '\n';
    if (stats.rules_enabled) {
        const auto& detection = stats.rules;
        output << "detection_summary packets=" << detection.packets_evaluated
               << " events=" << detection.events_emitted << " suppressed=" << detection.suppressed
               << " simulated_drops=" << detection.drops << " active=" << detection.active_flows
               << " state_bytes=" << detection.state_bytes
               << " peak_state_bytes=" << detection.peak_state_bytes
               << " mode=" << capture_mode_name(mode) << " enforced=false\n";
    }
}
void print_ended(const FlowEnd& ended, std::ostream& output) {
    for (const auto& stream : ended.streams) {
        if (stream) print_reassembly_event(*stream, output);
    }
}
struct ProcessingAbort {};

int analyze_capture(const std::string& path, FlowTableConfig config, TcpReassemblyConfig tcp_config,
                    const std::string& rule_path, RuleEngineConfig rule_config,
                    const std::string& log_path, std::ostream& output, std::ostream& errors,
                    CaptureMode mode, std::optional<std::uint64_t> packet_limit,
                    const StopRequest& stop) {
    try {
        std::optional<RuleSet> rules;
        if (!rule_path.empty()) rules = load_rule_file(rule_path);
        Engine engine(
            {config, tcp_config.stream_bytes, tcp_config.memory_bytes, rule_config.state_bytes},
            std::move(rules));
        const bool json_stdout = log_path == "-";
        std::optional<EventLogger> logger;
        if (json_stdout)
            logger.emplace(output);
        else if (!log_path.empty())
            logger.emplace(std::filesystem::path{log_path});
        bool aborted = false;
        bool log_reported = false;
        RunPublication run;
        run.mode = mode;
        run.interface = mode == CaptureMode::Live ? path : "";
        run.stop_reason = "error";
        std::optional<LivePcapSource> live;
        const auto report_log_failure = [&] {
            if (logger && logger->failed() && !log_reported) {
                log_reported = true;
                errors << "log_error: JSONL output failed; remaining inspection continued.\n";
                errors.flush();
            }
        };
        try {
            const PacketHandler consume = [&](const PacketEnvelope& envelope) {
                const auto result = engine.inspect(envelope);
                if (logger) publish_packet(*logger, result, run);
                if (mode == CaptureMode::Live) report_log_failure();
                if (!json_stdout) {
                    for (const auto& ended : result.expired) print_ended(ended, output);
                    if (result.packet && result.flow && !result.processing_error) {
                        print_packet(result.packet_number, *result.packet, *result.flow,
                                     result.reassembly, output);
                        if (result.reassembly) print_reassembly_event(*result.reassembly, output);
                        if (result.decision)
                            print_decision(result.packet_number, *result.flow, *result.decision,
                                           output, mode);
                    }
                }
                if (result.parse_error) {
                    errors << "parse_error packet=" << result.packet_number
                           << " reason=" << parse_error_name(*result.parse_error) << '\n';
                }
                if (result.flow && std::holds_alternative<FlowError>(*result.flow)) {
                    errors << "flow_error packet=" << result.packet_number
                           << " reason=capacity_exceeded\n";
                }
                if (result.processing_error) {
                    errors << "detection_error: " << result.processing_error->message << '\n';
                    throw ProcessingAbort{};
                }
                // JSON stdout failures belong to the logger and never stop inspection.
                if ((!json_stdout && !output) || !errors) {
                    throw std::runtime_error("Output stream failed.");
                }
            };
            if (mode == CaptureMode::Live) {
                live.emplace(LiveCaptureConfig{path, packet_limit});
                if (!live->activation_warning().empty()) {
                    errors << "capture_warning: " << live->activation_warning() << '\n';
                }
                errors << "live_ready interface=" << path << " mode=live enforced=false\n";
                errors.flush();
                if (!errors) throw std::runtime_error("Output stream failed.");
                const auto stopped = live->run(consume, stop);
                run.stop_reason = live_stop_name(stopped.reason);
                run.run_complete = true;
            } else {
                read_pcap(path, consume);
            }
        } catch (const ProcessingAbort&) {
            aborted = true;  // publish_packet already emitted the owned processing error.
        } catch (const std::exception& error) {
            aborted = true;
            errors << "capture_error: " << error.what() << '\n';
            if (logger) {
                EventContext context;
                context.mode = mode;
                context.captured_at = engine.stats().watermark;
                publish_error(*logger, context,
                              {"capture", "read_or_processing_failed", error.what()});
            }
        }
        if (live) run.capture = live->snapshot_stats();
        const auto ended = engine.finish(aborted                     ? EngineEnd::Aborted
                                         : mode == CaptureMode::Live ? EngineEnd::Stopped
                                                                     : EngineEnd::Eof);
        if (logger) publish_finish(*logger, ended, run);
        if (!json_stdout && !aborted) {
            for (const auto& flow : ended.flows) print_ended(flow, output);
            print_summary(ended.stats, output, mode);
        } else if (json_stdout)
            print_summary(ended.stats, errors, mode);
        if (mode == CaptureMode::Live && run.capture) {
            auto& summary = json_stdout ? errors : output;
            const auto& capture = *run.capture;
            summary << "capture_summary status="
                    << (capture.available ? "available" : "unavailable")
                    << " ps_recv=" << capture.received << " ps_drop=" << capture.dropped
                    << " ps_ifdrop=" << capture.interface_dropped
                    << " ifdrop_availability=platform_dependent"
                    << " stop_reason=" << run.stop_reason << '\n';
        }
        bool log_complete = true;
        if (logger) {
            log_complete = logger->finish();
            if (!log_complete) report_log_failure();
            const auto logs = logger->stats();
            errors << "logger_summary attempted=" << logs.attempted << " written=" << logs.written
                   << " failed=" << logs.failed_events << " dropped=" << logs.dropped
                   << " io_errors=" << logs.io_errors
                   << " alert_events_written=" << logs.alert_written
                   << " log_complete=" << (log_complete ? 1 : 0) << '\n';
        }
        if (!json_stdout) output.flush();
        errors.flush();
        if ((!json_stdout && !output) || !errors) {
            throw std::runtime_error("Output stream failed.");
        }
        return aborted || !log_complete || (!json_stdout && !output) || !errors ? 1 : 0;
    } catch (const RuleLoadError& error) {
        errors << "rule_error: " << error.what() << '\n';
    } catch (const LogOpenError& error) {
        errors << "log_error: " << error.what() << '\n';
    } catch (const std::exception& error) {
        errors << "capture_error: " << error.what() << '\n';
    }
    return 1;
}
int usage_error(std::ostream& errors) {
    errors << "Expected --help, --version, or --mode pcap --input PATH.\n" << HELP_TEXT;
    return 2;
}

}  // namespace

int run_cli(std::span<const std::string_view> arguments, std::ostream& output, std::ostream& errors,
            const StopRequest& stop) {
    if (arguments.size() == 1 && arguments.front() == "--help") {
        output << HELP_TEXT;
        return 0;
    }
    if (arguments.size() == 1 && arguments.front() == "--version") {
        output << "miniips " << MINIIPS_VERSION << '\n';
        return 0;
    }
    if (arguments.size() < 4 || arguments.size() % 2 != 0) {
        return usage_error(errors);
    }

    std::string_view mode;
    std::string_view input;
    std::string_view interface;
    std::optional<std::uint64_t> packet_limit;
    FlowTableConfig config;
    TcpReassemblyConfig tcp_config;
    RuleEngineConfig rule_config;
    std::string_view rule_path;
    std::string_view log_path;
    bool max_flows_seen = false;
    bool idle_timeout_seen = false;
    bool tcp_stream_seen = false;
    bool tcp_memory_seen = false;
    bool rule_state_seen = false;
    for (std::size_t index = 0; index < arguments.size(); index += 2) {
        const auto option = arguments[index];
        const auto value = arguments[index + 1];
        if (value.empty() || value.starts_with("--")) {
            return usage_error(errors);
        }
        if (option == "--mode" && mode.empty()) {
            mode = value;
        } else if (option == "--input" && input.empty()) {
            input = value;
        } else if (option == "--interface" && interface.empty()) {
            interface = value;
        } else if (option == "--packet-count" && !packet_limit) {
            packet_limit = positive_integer(value);
            if (!packet_limit) return usage_error(errors);
        } else if (option == "--max-flows" && !max_flows_seen) {
            const auto number = positive_integer(value);
            if (!number || *number > std::numeric_limits<std::size_t>::max()) {
                return usage_error(errors);
            }
            config.max_entries = static_cast<std::size_t>(*number);
            max_flows_seen = true;
        } else if (option == "--flow-idle-timeout-seconds" && !idle_timeout_seen) {
            const auto number = positive_integer(value);
            constexpr auto MAX_SECONDS = static_cast<std::uint64_t>(
                std::numeric_limits<std::int64_t>::max() / MICROSECONDS_PER_SECOND);
            if (!number || *number > MAX_SECONDS) {
                return usage_error(errors);
            }
            config.idle_timeout = std::chrono::microseconds{static_cast<std::int64_t>(*number) *
                                                            MICROSECONDS_PER_SECOND};
            idle_timeout_seen = true;
        } else if (option == "--tcp-stream-bytes" && !tcp_stream_seen) {
            const auto number = positive_integer(value);
            if (!number || *number >= 0x80000000ULL) {
                return usage_error(errors);
            }
            tcp_config.stream_bytes = static_cast<std::size_t>(*number);
            tcp_stream_seen = true;
        } else if (option == "--tcp-memory-bytes" && !tcp_memory_seen) {
            const auto number = positive_integer(value);
            if (!number || *number > std::numeric_limits<std::size_t>::max()) {
                return usage_error(errors);
            }
            tcp_config.memory_bytes = static_cast<std::size_t>(*number);
            tcp_memory_seen = true;
        } else if (option == "--rules" && rule_path.empty()) {
            rule_path = value;
        } else if (option == "--log" && log_path.empty()) {
            log_path = value;
        } else if (option == "--rule-state-bytes" && !rule_state_seen) {
            const auto number = positive_integer(value);
            if (!number || *number > std::numeric_limits<std::size_t>::max()) {
                return usage_error(errors);
            }
            rule_config.state_bytes = static_cast<std::size_t>(*number);
            rule_state_seen = true;
        } else {
            return usage_error(errors);
        }
    }
    if ((mode != "pcap" && mode != "live") || (rule_state_seen && rule_path.empty()) ||
        (mode == "pcap" && (input.empty() || !interface.empty() || packet_limit)) ||
        (mode == "live" && (interface.empty() || !input.empty()))) {
        return usage_error(errors);
    }
    tcp_config.max_flows = config.max_entries;
    rule_config.max_flows = config.max_entries;
    return analyze_capture(std::string{mode == "pcap" ? input : interface}, config, tcp_config,
                           std::string{rule_path}, rule_config, std::string{log_path}, output,
                           errors, mode == "pcap" ? CaptureMode::Pcap : CaptureMode::Live,
                           packet_limit, stop);
}

}  // namespace miniips
