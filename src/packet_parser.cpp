#include "miniips/packet_parser.hpp"

#include <cstddef>
#include <cstdint>
#include <span>

namespace miniips {
namespace {

constexpr std::size_t ETHERNET_HEADER_BYTES = 14;
constexpr std::size_t IPV4_MIN_HEADER_BYTES = 20;
constexpr std::size_t TCP_MIN_HEADER_BYTES = 20;
constexpr std::size_t UDP_HEADER_BYTES = 8;

// Callers establish the full header bounds before using these fixed field offsets.
std::uint16_t read_u16(std::span<const std::byte> bytes, std::size_t offset) noexcept {
    return static_cast<std::uint16_t>((std::to_integer<std::uint32_t>(bytes[offset]) << 8U) |
                                      std::to_integer<std::uint32_t>(bytes[offset + 1]));
}

std::uint32_t read_u32(std::span<const std::byte> bytes, std::size_t offset) noexcept {
    return (std::to_integer<std::uint32_t>(bytes[offset]) << 24U) |
           (std::to_integer<std::uint32_t>(bytes[offset + 1]) << 16U) |
           (std::to_integer<std::uint32_t>(bytes[offset + 2]) << 8U) |
           std::to_integer<std::uint32_t>(bytes[offset + 3]);
}

}  // namespace

ParseResult parse_packet(const PacketEnvelope& envelope) noexcept {
    if (envelope.layer != PacketLayer::Ethernet) {
        return ParseError::UnsupportedLinkLayer;
    }
    const auto frame = envelope.bytes;
    if (frame.size() > envelope.original_length) {
        return ParseError::InvalidCaptureLength;
    }
    if (frame.size() < envelope.original_length) {
        return ParseError::TruncatedCapture;
    }
    if (frame.size() < ETHERNET_HEADER_BYTES) {
        return ParseError::TruncatedEthernet;
    }
    if (read_u16(frame, 12) != 0x0800) {
        return ParseError::UnsupportedEtherType;
    }

    auto ip = frame.subspan(ETHERNET_HEADER_BYTES);
    if (ip.size() < IPV4_MIN_HEADER_BYTES) {
        return ParseError::TruncatedIpv4Header;
    }
    const auto version_ihl = std::to_integer<unsigned int>(ip[0]);
    if ((version_ihl >> 4U) != 4) {
        return ParseError::InvalidIpv4Version;
    }
    const std::size_t ip_header_bytes = static_cast<std::size_t>(version_ihl & 0x0FU) * 4U;
    if (ip_header_bytes < IPV4_MIN_HEADER_BYTES) {
        return ParseError::InvalidIpv4HeaderLength;
    }
    if (ip_header_bytes > ip.size()) {
        return ParseError::TruncatedIpv4Header;
    }
    const auto ip_total_length = read_u16(ip, 2);
    if (ip_total_length < ip_header_bytes) {
        return ParseError::InvalidIpv4TotalLength;
    }
    if (ip_total_length > ip.size()) {
        return ParseError::TruncatedIpv4Packet;
    }
    ip = ip.first(ip_total_length);

    const auto fragment = read_u16(ip, 6);
    if ((fragment & 0x8000U) != 0) {
        return ParseError::InvalidIpv4Flags;
    }
    if ((fragment & 0x3FFFU) != 0) {
        return ParseError::Ipv4Fragment;
    }
    const auto protocol = std::to_integer<std::uint8_t>(ip[9]);
    if (protocol != 6 && protocol != 17) {
        return ParseError::UnsupportedProtocol;
    }

    ParsedPacket packet;
    packet.captured_at = envelope.captured_at;
    packet.src_ip = read_u32(ip, 12);
    packet.dst_ip = read_u32(ip, 16);
    packet.ip_total_length = ip_total_length;
    packet.ip_header_bytes = ip_header_bytes;
    packet.protocol = static_cast<TransportProtocol>(protocol);
    const auto transport = ip.subspan(ip_header_bytes);

    if (packet.protocol == TransportProtocol::Tcp) {
        if (transport.size() < TCP_MIN_HEADER_BYTES) {
            return ParseError::TruncatedTcpHeader;
        }
        const std::size_t tcp_header_bytes =
            (std::to_integer<std::size_t>(transport[12]) >> 4U) * 4U;
        if (tcp_header_bytes < TCP_MIN_HEADER_BYTES || tcp_header_bytes > transport.size()) {
            return ParseError::InvalidTcpHeaderLength;
        }
        packet.transport_header_bytes = tcp_header_bytes;
        packet.tcp = TcpMetadata{read_u32(transport, 4), read_u32(transport, 8),
                                 std::to_integer<std::uint8_t>(transport[13])};
        packet.payload = transport.subspan(tcp_header_bytes);
    } else {
        if (transport.size() < UDP_HEADER_BYTES) {
            return ParseError::TruncatedUdpHeader;
        }
        const auto udp_length = read_u16(transport, 4);
        if (udp_length < UDP_HEADER_BYTES || udp_length != transport.size()) {
            return ParseError::InvalidUdpLength;
        }
        packet.transport_header_bytes = UDP_HEADER_BYTES;
        packet.payload = transport.subspan(UDP_HEADER_BYTES);
    }
    packet.src_port = read_u16(transport, 0);
    packet.dst_port = read_u16(transport, 2);
    return packet;
}

std::string_view parse_error_name(ParseError error) noexcept {
    switch (error) {
        case ParseError::UnsupportedLinkLayer:
            return "unsupported_link_layer";
        case ParseError::InvalidCaptureLength:
            return "invalid_capture_length";
        case ParseError::TruncatedCapture:
            return "truncated_capture";
        case ParseError::TruncatedEthernet:
            return "truncated_ethernet";
        case ParseError::UnsupportedEtherType:
            return "unsupported_ether_type";
        case ParseError::TruncatedIpv4Header:
            return "truncated_ipv4_header";
        case ParseError::InvalidIpv4Version:
            return "invalid_ipv4_version";
        case ParseError::InvalidIpv4HeaderLength:
            return "invalid_ipv4_header_length";
        case ParseError::InvalidIpv4TotalLength:
            return "invalid_ipv4_total_length";
        case ParseError::TruncatedIpv4Packet:
            return "truncated_ipv4_packet";
        case ParseError::InvalidIpv4Flags:
            return "invalid_ipv4_flags";
        case ParseError::Ipv4Fragment:
            return "ipv4_fragment";
        case ParseError::UnsupportedProtocol:
            return "unsupported_protocol";
        case ParseError::TruncatedTcpHeader:
            return "truncated_tcp_header";
        case ParseError::InvalidTcpHeaderLength:
            return "invalid_tcp_header_length";
        case ParseError::TruncatedUdpHeader:
            return "truncated_udp_header";
        case ParseError::InvalidUdpLength:
            return "invalid_udp_length";
    }
    return "unknown_parse_error";
}

}  // namespace miniips
