#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

#include "flow_fixtures.hpp"

namespace miniips::test {

struct TcpSegment {
    std::uint32_t sequence{};
    std::string_view payload{};
    std::uint8_t flags{0x18};
    bool backward{};
    std::uint16_t client_port{12345};
};

inline void put_be16(std::vector<std::byte>& bytes, std::size_t offset, std::uint16_t value) {
    bytes[offset] = static_cast<std::byte>(value >> 8U);
    bytes[offset + 1] = static_cast<std::byte>(value & 0xffU);
}

inline std::uint16_t checksum(std::span<const std::byte> bytes, std::uint32_t sum = 0) {
    for (std::size_t index = 0; index < bytes.size(); index += 2) {
        sum += std::to_integer<std::uint32_t>(bytes[index]) << 8U;
        if (index + 1 < bytes.size()) {
            sum += std::to_integer<std::uint32_t>(bytes[index + 1]);
        }
    }
    while ((sum >> 16U) != 0) {
        sum = (sum & 0xffffU) + (sum >> 16U);
    }
    return static_cast<std::uint16_t>(~sum & 0xffffU);
}

inline std::vector<std::byte> tcp_segment(TcpSegment segment) {
    if (segment.payload.size() > 65535 - 40) {
        throw std::invalid_argument("Fixture payload exceeds IPv4 size.");
    }
    auto bytes = segment.backward ? reverse_tcp_packet() : tcp_packet();
    bytes.resize(54 + segment.payload.size());
    put_be16(bytes, 16, static_cast<std::uint16_t>(40 + segment.payload.size()));
    put_be16(bytes, segment.backward ? 36U : 34U, segment.client_port);
    for (std::size_t index = 0; index < 4; ++index) {
        bytes[38 + index] = static_cast<std::byte>((segment.sequence >> ((3 - index) * 8)) & 0xffU);
        bytes[42 + index] = std::byte{0};
    }
    bytes[47] = static_cast<std::byte>(segment.flags);
    for (std::size_t index = 0; index < segment.payload.size(); ++index) {
        bytes[54 + index] = static_cast<std::byte>(segment.payload[index]);
    }
    put_be16(bytes, 24, 0);
    put_be16(bytes, 24, checksum(std::span{bytes}.subspan(14, 20)));
    put_be16(bytes, 50, 0);
    const auto pseudo_sum =
        static_cast<std::uint32_t>(~checksum(std::span{bytes}.subspan(26, 8)) & 0xffffU) + 6U +
        static_cast<std::uint32_t>(bytes.size() - 34);
    put_be16(bytes, 50, checksum(std::span{bytes}.subspan(34), pseudo_sum));
    return bytes;
}

}  // namespace miniips::test
