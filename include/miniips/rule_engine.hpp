#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <stdexcept>
#include <unordered_map>

#include "miniips/detection_decision.hpp"
#include "miniips/tcp_reassembler.hpp"

namespace miniips {

class DetectionError : public std::runtime_error {
   public:
    using std::runtime_error::runtime_error;
};
struct RuleEngineConfig {
    std::size_t max_flows{10000};
    std::size_t state_bytes{33554432};
};
struct RuleEngineStats {
    std::uint64_t packets_evaluated{};
    std::uint64_t events_emitted{};
    std::uint64_t suppressed{};
    std::uint64_t drops{};
    std::size_t active_flows{};
    std::size_t state_bytes{};
    std::size_t peak_state_bytes{};
};

// Single-threaded; consume tracked packets/expiry in FlowTable order.
// Input views are borrowed only for evaluate(). Decisions own their metadata.
class RuleEngine {
   public:
    explicit RuleEngine(RuleSet rules, RuleEngineConfig config = {});
    RuleEngine(const RuleEngine&) = delete;
    RuleEngine& operator=(const RuleEngine&) = delete;
    DetectionDecision evaluate(const ParsedPacket& packet, const FlowObservation* flow = nullptr,
                               const ReassemblyUpdate* stream = nullptr);
    void forget_flow(std::uint64_t id) noexcept;
    // Releases state but retains monotonic ID history; use a new engine per file.
    void clear() noexcept;
    RuleEngineStats stats() const noexcept;

   private:
    struct Entry {
        FlowKey key;
        FlowEndpoint first_source;
        std::array<std::unique_ptr<std::uint64_t[]>, 2> ends;
    };
    std::uint64_t* watermark(Entry& entry, FlowDirection direction);
    RuleSet rules_;
    RuleEngineConfig config_;
    std::unordered_map<std::uint64_t, Entry> flows_;
    std::uint64_t highest_id_{};
    RuleEngineStats stats_;
};

}  // namespace miniips
