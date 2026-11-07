#pragma once

#include <chrono>
#include <compare>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <variant>

#include "miniips/packet.hpp"

namespace miniips {

struct FlowEndpoint {
    std::uint32_t ip{};
    std::uint16_t port{};
    auto operator<=>(const FlowEndpoint&) const = default;
};

struct FlowKey {
    FlowEndpoint low;
    FlowEndpoint high;
    TransportProtocol protocol{TransportProtocol::Tcp};
    bool operator==(const FlowKey&) const = default;
};

struct FlowKeyHash {
    std::size_t operator()(const FlowKey& key) const noexcept;
};

// Ordering identifies a bidirectional tuple, not its first observed direction.
FlowKey make_flow_key(const ParsedPacket& packet);

enum class FlowDirection : std::uint8_t { Forward, Backward };
enum class TcpFlowState : std::uint8_t { Observed, SynSeen, Established, Closing, Closed, Reset };

struct FlowDirectionStats {
    std::uint64_t packets{};
    std::uint64_t bytes{};
    std::uint64_t iat_sum_us{};
    std::uint64_t iat_samples{};
    std::optional<std::chrono::microseconds> last_seen;
    std::uint64_t syn_count{};
    std::uint64_t ack_count{};
    std::uint64_t fin_count{};
    std::uint64_t rst_count{};
    std::uint64_t psh_count{};
};

// Fixed-size owned metadata. No packet buffer or borrowed payload is retained.
struct FlowSnapshot {
    std::uint64_t flow_id{};
    FlowKey key;
    FlowEndpoint first_source;
    std::chrono::microseconds first_seen{};
    std::chrono::microseconds last_seen{};
    FlowDirectionStats fwd;
    FlowDirectionStats bwd;
    std::optional<TcpFlowState> tcp_state;
};

struct FlowObservation {
    FlowSnapshot flow;
    FlowDirection direction{FlowDirection::Forward};
    bool created{};
};

enum class FlowError : std::uint8_t { CapacityExceeded };
using FlowResult = std::variant<FlowObservation, FlowError>;

struct FlowTableConfig {
    std::size_t max_entries{10000};
    std::chrono::microseconds idle_timeout{std::chrono::seconds{120}};
};

struct FlowTableStats {
    std::uint64_t created{};
    std::uint64_t expired{};
    std::uint64_t rejected{};
    std::size_t active{};
};

}  // namespace miniips
