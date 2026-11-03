#include "miniips/cli.hpp"

#include <cstddef>
#include <cstdint>
#include <exception>
#include <ostream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>

#include "miniips/capture_source.hpp"
#include "miniips/packet_parser.hpp"

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
    "\n"
    "A1: metadata only; detection, live capture and blocking are not implemented.\n";

std::string ipv4_text(std::uint32_t address) {
    return std::to_string((address >> 24U) & 0xFFU) + "." +
           std::to_string((address >> 16U) & 0xFFU) + "." +
           std::to_string((address >> 8U) & 0xFFU) + "." + std::to_string(address & 0xFFU);
}

void print_packet(std::uint64_t number, const ParsedPacket& packet, std::ostream& output) {
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
    output << '\n';
}

int analyze_pcap(const std::string& path, std::ostream& output, std::ostream& errors) {
    std::uint64_t packets = 0;
    std::uint64_t parsed = 0;
    std::uint64_t skipped = 0;
    try {
        read_pcap(path, [&](const PacketEnvelope& envelope) {
            ++packets;
            const auto result = parse_packet(envelope);
            if (const auto* packet = std::get_if<ParsedPacket>(&result)) {
                print_packet(packets, *packet, output);
                ++parsed;
            } else {
                errors << "parse_error packet=" << packets
                       << " reason=" << parse_error_name(std::get<ParseError>(result)) << '\n';
                ++skipped;
            }
            if (!output || !errors) {
                throw std::runtime_error("Output stream failed.");
            }
        });
        output << "pcap_summary packets=" << packets << " parsed=" << parsed
               << " skipped=" << skipped << '\n';
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
    if (arguments.size() != 4) {
        return usage_error(errors);
    }

    std::string_view mode;
    std::string_view input;
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
        } else {
            return usage_error(errors);
        }
    }
    if (mode != "pcap" || input.empty()) {
        return usage_error(errors);
    }
    return analyze_pcap(std::string{input}, output, errors);
}

}  // namespace miniips
