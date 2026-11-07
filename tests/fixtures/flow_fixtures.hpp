#pragma once

#include <cstddef>
#include <cstdint>
#include <utility>
#include <vector>

#include "../pcap_fixture.hpp"
#include "packet_fixtures.hpp"

namespace miniips::test {

// Reverse the fixed Ethernet, IPv4 and TCP endpoints, preserving the byte sum.
inline std::vector<std::byte> reverse_tcp_packet() {
    auto bytes = tcp_packet();
    for (std::size_t index = 0; index < 6; ++index) {
        std::swap(bytes[index], bytes[index + 6]);
    }
    for (std::size_t index = 0; index < 4; ++index) {
        std::swap(bytes[26 + index], bytes[30 + index]);
    }
    for (std::size_t index = 0; index < 2; ++index) {
        std::swap(bytes[34 + index], bytes[36 + index]);
    }
    return bytes;
}

inline PcapRecord record_at(std::vector<std::byte> bytes, std::uint32_t seconds) {
    auto item = record(std::move(bytes));
    item.seconds = seconds;
    item.fractional = 0;
    return item;
}

}  // namespace miniips::test
