#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>

#include "miniips/packet.hpp"

namespace miniips {

enum class CaptureMode : std::uint8_t { Pcap, Live };
constexpr std::string_view capture_mode_name(CaptureMode mode) noexcept {
    return mode == CaptureMode::Pcap ? "pcap" : mode == CaptureMode::Live ? "live" : "unknown";
}
enum class LiveStopReason : std::uint8_t { Requested, Sigint, Sigterm, PacketLimit };
constexpr std::string_view live_stop_name(LiveStopReason reason) noexcept {
    switch (reason) {
        case LiveStopReason::Requested:
            return "requested";
        case LiveStopReason::Sigint:
            return "sigint";
        case LiveStopReason::Sigterm:
            return "sigterm";
        case LiveStopReason::PacketLimit:
            return "packet_limit";
    }
    return "unknown";
}
using StopRequest = std::function<std::optional<LiveStopReason>()>;
struct CaptureStats {
    bool available{};
    std::uint64_t received{}, dropped{}, interface_dropped{};
    unsigned int counter_bits{};
    std::string error;
};

using PacketHandler = std::function<void(const PacketEnvelope&)>;

// Reads an offline Ethernet capture to EOF, closing it on every return/exception.
// The handler must consume/copy borrowed bytes before returning.
// Throws on open/read/link-type/timestamp errors; propagates handler exceptions.
// A path of "-" (stdin) is intentionally unsupported.
void read_pcap(const std::string& path, const PacketHandler& on_packet);

}  // namespace miniips
