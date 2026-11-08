#pragma once

#include <string_view>

#include "miniips/engine.hpp"
#include "miniips/event_logger.hpp"

namespace miniips {
// Synchronous publication of one owned result. Failures latch in the logger;
// neither publication nor a failed sink changes any Engine decision.
void publish_packet(EventLogger& logger, const PacketResult& result) noexcept;
void publish_finish(EventLogger& logger, const FinishResult& result) noexcept;
struct ErrorInfo {
    std::string_view domain;
    std::string_view reason;
    std::string_view message;
};
void publish_error(EventLogger& logger, const EventContext& context, ErrorInfo error) noexcept;
}  // namespace miniips
