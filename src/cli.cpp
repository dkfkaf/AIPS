#include "miniips/cli.hpp"

#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <limits>
#include <optional>
#include <ostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <variant>

#include "miniips/capture_source.hpp"
#include "miniips/flow_table.hpp"
#include "miniips/packet_parser.hpp"
#include "miniips/tcp_reassembler.hpp"

namespace miniips {
namespace {

constexpr std::string_view HELP_TEXT =
    "Usage: miniips --help | --version\n"
    "       miniips --mode pcap --input <file.pcap>\n"
    "\n"
    "Options:\n"
    "  --help       Show this help message.\n"
    "  --version    Show the program version.\n"
    "  --mode pcap  Analyze an offline Ethernet IPv4 TCP/UDP capture.\n"
    "  --input PATH Read packets from this capture file.\n"
    "  --max-flows N Limit active flows (default: 10000).\n"
    "  --flow-idle-timeout-seconds N Expire idle flows (default: 120).\n"
    "  --tcp-stream-bytes N Limit each TCP prefix/depth (default: 65536).\n"
    "  --tcp-memory-bytes N Limit TCP payload arrays + bitmaps (default: 134217728).\n"
    "\n"
    "A3: offline bounded TCP prefixes; detection, live capture and blocking are not implemented.\n"
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

void print_stream_fields(const ReassemblyUpdate& update, std::ostream& output) {
    output << " stream_bytes=" << update.contiguous_prefix.size()
           << " stream_new_bytes=" << update.newly_contiguous.size()
           << " stream_pending_bytes=" << update.pending_bytes
           << " stream_closed=" << (update.closed ? 1 : 0) << " issues=";
    print_issues(update.issues, output);
}

void print_reassembly_event(const ReassemblyUpdate& update, std::ostream& output) {
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

void print_packet(std::uint64_t number, const ParsedPacket& packet, const FlowResult& result,
                  const std::optional<ReassemblyUpdate>& reassembly, std::ostream& output) {
    output << "packet=" << number << " timestamp_us=" << packet.captured_at.count()
           << " protocol=" << (packet.protocol == TransportProtocol::Tcp ? "tcp" : "udp")
           << " src_ip=" << ipv4_text(packet.src_ip) << " src_port=" << packet.src_port
           << " dst_ip=" << ipv4_text(packet.dst_ip) << " dst_port=" << packet.dst_port
           << " ip_bytes=" << packet.ip_total_length
           << " ip_header_bytes=" << packet.ip_header_bytes
           << " transport_header_bytes=" << packet.transport_header_bytes
           << " payload_bytes=" << packet.payload.size();
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

int analyze_pcap(const std::string& path, FlowTableConfig config, TcpReassemblyConfig tcp_config,
                 std::ostream& output, std::ostream& errors) {
    std::uint64_t packets = 0;
    std::uint64_t parsed = 0;
    std::uint64_t skipped = 0;
    try {
        FlowTable flows(config);
        TcpReassembler reassembler(tcp_config);
        const ReassemblyEventSink event_sink = [&](const ReassemblyUpdate& update) {
            print_reassembly_event(update, output);
        };
        const FlowExpirySink on_expire = [&](const FlowSnapshot& flow) {
            reassembler.finish_flow(flow.flow_id, ReassemblyEnd::IdleTimeout, event_sink);
        };
        read_pcap(path, [&](const PacketEnvelope& envelope) {
            ++packets;
            const auto result = parse_packet(envelope);
            if (const auto* packet = std::get_if<ParsedPacket>(&result)) {
                const auto tracked = flows.observe(*packet, on_expire);
                if (std::holds_alternative<FlowError>(tracked)) {
                    errors << "flow_error packet=" << packets << " reason=capacity_exceeded\n";
                }
                std::optional<ReassemblyUpdate> reassembly;
                if (packet->protocol == TransportProtocol::Tcp) {
                    if (const auto* flow = std::get_if<FlowObservation>(&tracked)) {
                        reassembly = reassembler.observe(*flow, *packet);
                    }
                }
                print_packet(packets, *packet, tracked, reassembly, output);
                if (reassembly) {
                    print_reassembly_event(*reassembly, output);
                }
                ++parsed;
            } else {
                flows.expire(envelope.captured_at, on_expire);
                errors << "parse_error packet=" << packets
                       << " reason=" << parse_error_name(std::get<ParseError>(result)) << '\n';
                ++skipped;
            }
            if (!output || !errors) {
                throw std::runtime_error("Output stream failed.");
            }
        });
        reassembler.finish_all(ReassemblyEnd::CaptureEnd, event_sink);
        output << "pcap_summary packets=" << packets << " parsed=" << parsed
               << " skipped=" << skipped << '\n';
        const auto stats = flows.stats();
        output << "flow_summary created=" << stats.created << " active=" << stats.active
               << " expired=" << stats.expired << " rejected=" << stats.rejected << '\n';
        const auto tcp_stats = reassembler.stats();
        output << "reassembly_summary bytes_emitted=" << tcp_stats.bytes_emitted
               << " overlap_conflicts=" << tcp_stats.overlap_conflicts
               << " rejected=" << tcp_stats.rejected << " active=" << tcp_stats.active_flows
               << " memory_bytes=" << tcp_stats.memory_bytes
               << " peak_memory_bytes=" << tcp_stats.peak_memory_bytes << '\n';
        output.flush();
        errors.flush();
        if (!output || !errors) {
            throw std::runtime_error("Output stream failed.");
        }
        return 0;
    } catch (const std::exception& error) {
        errors << "capture_error: " << error.what() << '\n';
        return 1;
    }
}

int usage_error(std::ostream& errors) {
    errors << "Expected --help, --version, or --mode pcap --input PATH.\n" << HELP_TEXT;
    return 2;
}

}  // namespace

int run_cli(std::span<const std::string_view> arguments, std::ostream& output,
            std::ostream& errors) {
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
    FlowTableConfig config;
    TcpReassemblyConfig tcp_config;
    bool max_flows_seen = false;
    bool idle_timeout_seen = false;
    bool tcp_stream_seen = false;
    bool tcp_memory_seen = false;
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
        } else {
            return usage_error(errors);
        }
    }
    if (mode != "pcap" || input.empty()) {
        return usage_error(errors);
    }
    tcp_config.max_flows = config.max_entries;
    return analyze_pcap(std::string{input}, config, tcp_config, output, errors);
}

}  // namespace miniips
