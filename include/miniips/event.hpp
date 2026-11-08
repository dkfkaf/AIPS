#pragma once

#include <chrono>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <optional>
#include <string>
#include <string_view>

#include "miniips/capture_source.hpp"
#include "miniips/flow.hpp"

namespace miniips {

enum class EventType : std::uint8_t {
    Alert,
    Verdict,
    Flow,
    ParseError,
    ReassemblyWarning,
    Stats,
    EngineError
};
enum class EventAction : std::uint8_t { Alert, Drop, Pass, Allow, Skip, Observe, Error, None };
std::string_view event_type_name(EventType type) noexcept;
std::string_view event_action_name(EventAction action) noexcept;

struct EventContext {
    CaptureMode mode{CaptureMode::Pcap};
    bool enforced{};
    std::optional<std::chrono::microseconds> captured_at;
    std::optional<std::uint64_t> packet_number;
    std::optional<std::uint64_t> flow_id;
    std::optional<FlowEndpoint> source;
    std::optional<FlowEndpoint> destination;
    std::optional<TransportProtocol> protocol;
    std::optional<FlowDirection> direction;
};

struct Event {
    EventType type{EventType::Flow};
    EventAction action{EventAction::Observe};
    EventContext context;
    std::optional<std::uint32_t> sid;
    std::string message;
    bool message_truncated{};
    // Publisher-owned schema additions. Cannot override common/reserved keys.
    nlohmann::json fields = nlohmann::json::object();
};

}  // namespace miniips
