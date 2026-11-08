#pragma once

#include <pcap/pcap.h>

#include <chrono>
#include <cstdint>
#include <limits>
#include <stdexcept>

namespace miniips::detail {
inline constexpr int MAX_CAPTURE_BYTES = 262144;
inline std::chrono::microseconds capture_time(const pcap_pkthdr& header) {
    constexpr std::int64_t MICROSECONDS_PER_SECOND = 1000000;
    const auto seconds = static_cast<std::int64_t>(header.ts.tv_sec);
    const auto microseconds = static_cast<std::int64_t>(header.ts.tv_usec);
    if (seconds < 0 || microseconds < 0 || microseconds >= MICROSECONDS_PER_SECOND) {
        throw std::runtime_error("Invalid PCAP timestamp.");
    }
    if (seconds >
        (std::numeric_limits<std::int64_t>::max() - microseconds) / MICROSECONDS_PER_SECOND) {
        throw std::runtime_error("PCAP timestamp overflows microseconds.");
    }
    return std::chrono::microseconds{seconds * MICROSECONDS_PER_SECOND + microseconds};
}
}  // namespace miniips::detail
