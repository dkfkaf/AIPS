#pragma once

#include <array>
#include <bitset>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <unordered_map>

#include "miniips/flow.hpp"

namespace miniips {

enum class SequenceOrder : std::uint8_t { Before, Equal, After, Ambiguous };
SequenceOrder compare_tcp_sequence(std::uint32_t lhs, std::uint32_t rhs) noexcept;

enum class ReassemblyIssue : std::uint8_t {
    Midstream,
    BeforeAnchor,
    GapPending,
    GapFilled,
    Gap,
    OverlapConflict,
    DepthLimit,
    MemoryLimit,
    CapacityLimit,
    SequenceAmbiguous,
    InvalidSegment,
    SessionReuse,
    Reset,
    IdleTimeout,
    CaptureEnd,
    Count
};
using ReassemblyIssues = std::bitset<static_cast<std::size_t>(ReassemblyIssue::Count)>;
bool has_issue(const ReassemblyIssues& issues, ReassemblyIssue issue) noexcept;
std::string_view reassembly_issue_name(ReassemblyIssue issue) noexcept;
enum class ReassemblyEnd : std::uint8_t { IdleTimeout, CaptureEnd };

struct TcpReassemblyConfig {
    std::size_t stream_bytes{65536};
    std::size_t memory_bytes{134217728};
    std::size_t max_flows{10000};
};

// Views are valid only until the next non-const reassembler operation.
// 'closed' means an observed FIN has no preceding gap, never full inspection.
struct ReassemblyUpdate {
    std::uint64_t flow_id{};
    FlowDirection direction{FlowDirection::Forward};
    std::span<const std::byte> contiguous_prefix;
    std::span<const std::byte> newly_contiguous;
    std::size_t pending_bytes{};
    ReassemblyIssues issues;
    ReassemblyIssues events;
    bool fin_seen{};
    bool closed{};
    std::optional<ReassemblyEnd> end;
};
using ReassemblyEventSink = std::function<void(const ReassemblyUpdate&)>;

struct TcpReassemblyStats {
    std::uint64_t bytes_emitted{};
    std::uint64_t overlap_conflicts{};
    std::uint64_t rejected{};
    std::size_t active_flows{};
    std::size_t memory_bytes{};
    std::size_t peak_memory_bytes{};
};

// Single-threaded. Consume every tracked TCP observation, in FlowTable order.
// New IDs must increase as assigned by that table; IDs are never reused.
// Sinks run synchronously and must not reenter or mutate this object.
class TcpReassembler {
   public:
    explicit TcpReassembler(TcpReassemblyConfig config = {});
    ReassemblyUpdate observe(const FlowObservation& flow, const ParsedPacket& packet);
    // Sink exceptions propagate after removing this flow. finish_all also removes
    // all remaining state on exception. Views must not escape the sink call.
    void finish_flow(std::uint64_t flow_id, ReassemblyEnd reason, const ReassemblyEventSink& sink);
    void finish_all(ReassemblyEnd reason, const ReassemblyEventSink& sink);
    TcpReassemblyStats stats() const noexcept;

   private:
    struct Stream {
        bool seen{};
        bool anchored{};
        bool disabled{};
        std::uint32_t anchor{};
        std::optional<std::uint32_t> syn_sequence;
        std::optional<std::int64_t> fin_offset;
        std::unique_ptr<std::byte[]> data;
        std::unique_ptr<std::byte[]> present;
        std::size_t contiguous{};
        std::size_t stored{};
        std::size_t highest_end{};
        ReassemblyIssues issues;
    };
    struct Entry {
        FlowKey key;
        FlowEndpoint first_source;
        std::array<Stream, 2> streams;
        bool reset{};
    };

    static bool gap_pending(const Stream& stream) noexcept;
    static void note(Stream& stream, ReassemblyIssue issue, ReassemblyIssues& events);
    static ReassemblyUpdate snapshot(std::uint64_t id, FlowDirection direction,
                                     const Stream& stream);
    void process(Stream& stream, const ParsedPacket& packet, TcpMetadata tcp,
                 ReassemblyIssues& events);
    bool allocate(Stream& stream, ReassemblyIssues& events);
    void release(Stream& stream) noexcept;
    void remove(std::unordered_map<std::uint64_t, Entry>::iterator position) noexcept;

    TcpReassemblyConfig config_;
    std::size_t bitmap_bytes_{};
    std::size_t direction_bytes_{};
    std::unordered_map<std::uint64_t, Entry> flows_;
    std::uint64_t highest_id_{};
    TcpReassemblyStats stats_;
};

}  // namespace miniips
