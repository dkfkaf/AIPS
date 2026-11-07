#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <unordered_map>

#include "miniips/flow.hpp"

namespace miniips {

// Runs synchronously immediately before erasure. Must not reenter this table.
// Exceptions propagate; that flow remains, previously completed erasures count.
using FlowExpirySink = std::function<void(const FlowSnapshot&)>;

// Single-threaded table. Returned snapshots remain valid after updates/expiry.
class FlowTable {
   public:
    // Rejects zero capacity and nonpositive idle time with invalid_argument.
    explicit FlowTable(FlowTableConfig config = {});

    // Consumes parsed IPv4 TCP/UDP metadata. Invalid metadata throws before mutation.
    // Expiration precedes lookup; capacity rejects new keys, never existing keys.
    FlowResult observe(const ParsedPacket& packet, const FlowExpirySink& on_expire = {});

    // Monotonic capture watermark: backwards calls cannot rewind idle expiration.
    // Entries expire when idle time is >= timeout. Negative time is invalid.
    std::size_t expire(std::chrono::microseconds now, const FlowExpirySink& on_expire = {});
    std::optional<FlowSnapshot> find(const FlowKey& key) const;
    FlowTableStats stats() const noexcept;
    std::size_t size() const noexcept;

   private:
    struct Entry {
        FlowSnapshot snapshot;
        std::chrono::microseconds last_activity{};
        std::optional<FlowDirection> syn_initiator;
        bool syn_ack_seen{};
        bool forward_fin{};
        bool backward_fin{};
    };

    static void update_tcp_state(Entry& entry, const ParsedPacket& packet, FlowDirection direction);
    static void update_entry(Entry& entry, const ParsedPacket& packet, FlowDirection direction);

    FlowTableConfig config_;
    std::unordered_map<FlowKey, Entry, FlowKeyHash> flows_;
    std::chrono::microseconds watermark_{};
    std::uint64_t created_{};
    std::uint64_t expired_{};
    std::uint64_t rejected_{};
};

}  // namespace miniips
