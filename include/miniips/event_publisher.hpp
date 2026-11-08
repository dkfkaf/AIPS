#pragma once

#include <string_view>

#include "miniips/engine.hpp"
#include "miniips/event_logger.hpp"

namespace miniips {
struct RunPublication {
    CaptureMode mode{CaptureMode::Pcap};
    std::string interface;
    std::optional<CaptureStats> capture;
    std::string stop_reason;
    bool run_complete{};
};
// Synchronous publication of one owned result. Failures latch in the logger;
// neither publication nor a failed sink changes any Engine decision.
void publish_packet(EventLogger& logger, const PacketResult& result,
                    const RunPublication& run = {}) noexcept;
void publish_finish(EventLogger& logger, const FinishResult& result,
                    const RunPublication& run = {}) noexcept;
struct ErrorInfo {
    std::string_view domain;
    std::string_view reason;
    std::string_view message;
};
void publish_error(EventLogger& logger, const EventContext& context, ErrorInfo error) noexcept;
}  // namespace miniips
