#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace miniips {

enum class PacketLayer { Ethernet };
enum class TransportProtocol : std::uint8_t { Tcp = 6, Udp = 17 };

// bytes is a borrowed capture view; original_length is the on-wire frame length.
struct PacketEnvelope {
    std::span<const std::byte> bytes;
    std::uint32_t original_length{};
    std::chrono::microseconds captured_at{};
    PacketLayer layer{PacketLayer::Ethernet};
};

struct TcpMetadata {
    std::uint32_t sequence_number{};
    std::uint32_t acknowledgement_number{};
    std::uint8_t flags{};
};

// IPv4 addresses are numeric big-endian values, independent of host byte order.
// payload borrows PacketEnvelope::bytes and must not outlive that storage.
struct ParsedPacket {
    std::chrono::microseconds captured_at{};
    std::uint32_t src_ip{};
    std::uint32_t dst_ip{};
    std::uint16_t src_port{};
    std::uint16_t dst_port{};
    std::uint16_t ip_total_length{};
    std::size_t ip_header_bytes{};
    std::size_t transport_header_bytes{};
    TransportProtocol protocol{TransportProtocol::Tcp};
    std::optional<TcpMetadata> tcp;
    std::span<const std::byte> payload;
};

}  // namespace miniips
