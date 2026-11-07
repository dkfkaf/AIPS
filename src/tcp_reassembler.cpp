#include "miniips/tcp_reassembler.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <stdexcept>

namespace miniips {
namespace {

constexpr std::uint32_t HALF_SPACE = 0x80000000U;

TcpMetadata validate_observation(const FlowObservation& flow, const ParsedPacket& packet) {
    const auto headers = packet.ip_header_bytes + packet.transport_header_bytes;
    const bool valid_headers =
        packet.ip_header_bytes >= 20 && packet.ip_header_bytes <= 60 &&
        packet.ip_header_bytes % 4 == 0 && packet.transport_header_bytes >= 20 &&
        packet.transport_header_bytes <= 60 && packet.transport_header_bytes % 4 == 0;
    const auto expected_direction =
        FlowEndpoint{packet.src_ip, packet.src_port} == flow.flow.first_source
            ? FlowDirection::Forward
            : FlowDirection::Backward;
    if (flow.flow.flow_id == 0 || packet.protocol != TransportProtocol::Tcp || !packet.tcp ||
        packet.captured_at.count() < 0 || !valid_headers || headers > packet.ip_total_length ||
        packet.payload.size() != packet.ip_total_length - headers ||
        flow.flow.key != make_flow_key(packet) ||
        (flow.flow.first_source != flow.flow.key.low &&
         flow.flow.first_source != flow.flow.key.high) ||
        flow.direction != expected_direction) {
        throw std::invalid_argument("Reassembly requires a consistent tracked IPv4 TCP packet.");
    }
    return *packet.tcp;
}

bool present_at(const std::byte* bitmap, std::size_t offset) noexcept {
    return (std::to_integer<unsigned int>(bitmap[offset / 8]) & (1U << (offset % 8))) != 0;
}

}  // namespace

SequenceOrder compare_tcp_sequence(std::uint32_t lhs, std::uint32_t rhs) noexcept {
    const std::uint32_t delta = lhs - rhs;
    if (delta == 0) {
        return SequenceOrder::Equal;
    }
    if (delta == HALF_SPACE) {
        return SequenceOrder::Ambiguous;
    }
    return delta < HALF_SPACE ? SequenceOrder::After : SequenceOrder::Before;
}

bool has_issue(const ReassemblyIssues& issues, ReassemblyIssue issue) noexcept {
    const auto index = static_cast<std::size_t>(issue);
    return index < issues.size() && issues[index];
}

std::string_view reassembly_issue_name(ReassemblyIssue issue) noexcept {
    constexpr std::array<std::string_view, static_cast<std::size_t>(ReassemblyIssue::Count)> NAMES{
        "midstream",        "before_anchor", "gap_pending",  "gap_filled",     "gap",
        "overlap_conflict", "depth_limit",   "memory_limit", "capacity_limit", "sequence_ambiguous",
        "invalid_segment",  "session_reuse", "reset",        "idle_timeout",   "capture_end"};
    const auto index = static_cast<std::size_t>(issue);
    return index < NAMES.size() ? NAMES[index] : "unknown";
}

TcpReassembler::TcpReassembler(TcpReassemblyConfig config) : config_(config) {
    if (config_.stream_bytes == 0 || config_.stream_bytes >= HALF_SPACE ||
        config_.memory_bytes == 0 || config_.max_flows == 0) {
        throw std::invalid_argument("Invalid TCP reassembly depth, memory or flow limit.");
    }
    bitmap_bytes_ = (config_.stream_bytes + 7) / 8;
    direction_bytes_ = config_.stream_bytes + bitmap_bytes_;
}

bool TcpReassembler::gap_pending(const Stream& stream) noexcept {
    // Reset preserves earlier gap history, but released bytes cannot be pending.
    return !has_issue(stream.issues, ReassemblyIssue::Reset) &&
           (stream.stored > stream.contiguous ||
            (stream.fin_offset &&
             *stream.fin_offset > static_cast<std::int64_t>(stream.contiguous)));
}

void TcpReassembler::note(Stream& stream, ReassemblyIssue issue, ReassemblyIssues& events) {
    const auto index = static_cast<std::size_t>(issue);
    stream.issues.set(index);
    events.set(index);
}

ReassemblyUpdate TcpReassembler::snapshot(std::uint64_t id, FlowDirection direction,
                                          const Stream& stream) {
    ReassemblyUpdate result;
    result.flow_id = id;
    result.direction = direction;
    if (stream.data) {
        result.contiguous_prefix = {stream.data.get(), stream.contiguous};
    }
    result.pending_bytes = stream.stored - stream.contiguous;
    result.issues = stream.issues;
    result.issues.set(static_cast<std::size_t>(ReassemblyIssue::GapPending), gap_pending(stream));
    result.fin_seen = stream.fin_offset.has_value();
    result.closed = !has_issue(stream.issues, ReassemblyIssue::Reset) && stream.fin_offset &&
                    *stream.fin_offset == static_cast<std::int64_t>(stream.contiguous);
    return result;
}

bool TcpReassembler::allocate(Stream& stream, ReassemblyIssues& events) {
    if (stream.data) {
        return true;
    }
    if (direction_bytes_ > config_.memory_bytes - stats_.memory_bytes) {
        note(stream, ReassemblyIssue::MemoryLimit, events);
        stream.disabled = true;
        ++stats_.rejected;
        return false;
    }
    auto data = std::make_unique<std::byte[]>(config_.stream_bytes);
    auto present = std::make_unique<std::byte[]>(bitmap_bytes_);
    stream.data = std::move(data);
    stream.present = std::move(present);
    stats_.memory_bytes += direction_bytes_;
    stats_.peak_memory_bytes = std::max(stats_.peak_memory_bytes, stats_.memory_bytes);
    return true;
}

void TcpReassembler::release(Stream& stream) noexcept {
    if (stream.data) {
        stats_.memory_bytes -= direction_bytes_;
        stream.data.reset();
        stream.present.reset();
    }
    stream.contiguous = 0;
    stream.stored = 0;
    stream.highest_end = 0;
}

void TcpReassembler::process(Stream& stream, const ParsedPacket& packet, TcpMetadata tcp,
                             ReassemblyIssues& events, std::optional<ByteRange>& accepted) {
    const bool syn = (tcp.flags & 0x02U) != 0;
    const bool fin = (tcp.flags & 0x01U) != 0;
    const std::uint32_t data_sequence = tcp.sequence_number + (syn ? 1U : 0U);
    if (syn) {
        if ((stream.syn_sequence && *stream.syn_sequence != tcp.sequence_number) ||
            (stream.anchored && stream.anchor != data_sequence)) {
            note(stream, ReassemblyIssue::SessionReuse, events);
            stream.disabled = true;
            return;
        }
        stream.syn_sequence = tcp.sequence_number;
        stream.anchor = data_sequence;
        stream.anchored = true;
    }
    if (stream.disabled || (packet.payload.empty() && !fin)) {
        return;
    }
    if (!stream.anchored) {
        stream.anchor = data_sequence;
        stream.anchored = true;
        note(stream, ReassemblyIssue::Midstream, events);
    }
    if (compare_tcp_sequence(data_sequence, stream.anchor) == SequenceOrder::Ambiguous) {
        note(stream, ReassemblyIssue::SequenceAmbiguous, events);
        return;
    }
    const std::uint32_t delta = data_sequence - stream.anchor;
    const auto offset = delta < HALF_SPACE ? static_cast<std::int64_t>(delta)
                                           : -static_cast<std::int64_t>(0x100000000ULL - delta);
    const auto end = offset + static_cast<std::int64_t>(packet.payload.size());
    // The FIN boundary (not just the first byte) must fit the unambiguous
    // anchored interval. Such data also exceeds every supported prefix depth.
    if (end >= HALF_SPACE) {
        note(stream, ReassemblyIssue::SequenceAmbiguous, events);
        return;
    }
    if (offset < 0) {
        note(stream, ReassemblyIssue::BeforeAnchor, events);
    }
    if (fin && (end < 0 || end < static_cast<std::int64_t>(stream.highest_end) ||
                (stream.fin_offset && *stream.fin_offset != end))) {
        note(stream, ReassemblyIssue::InvalidSegment, events);
        return;
    }
    if (end > static_cast<std::int64_t>(config_.stream_bytes)) {
        note(stream, ReassemblyIssue::DepthLimit, events);
    }
    auto allowed_end = std::min(end, static_cast<std::int64_t>(config_.stream_bytes));
    if (stream.fin_offset && end > *stream.fin_offset) {
        note(stream, ReassemblyIssue::InvalidSegment, events);
        allowed_end = std::min(allowed_end, *stream.fin_offset);
    }
    const auto start = std::max<std::int64_t>(offset, 0);
    if (allowed_end > start && allocate(stream, events)) {
        bool conflict = false;
        for (auto location = start; location < allowed_end; ++location) {
            const auto index = static_cast<std::size_t>(location);
            const auto byte = packet.payload[static_cast<std::size_t>(location - offset)];
            if (present_at(stream.present.get(), index)) {
                conflict = conflict || stream.data[index] != byte;
            } else {
                stream.data[index] = byte;
                stream.present[index / 8] |= static_cast<std::byte>(1U << (index % 8));
                ++stream.stored;
                stream.highest_end = std::max(stream.highest_end, index + 1);
            }
        }
        if (conflict) {
            note(stream, ReassemblyIssue::OverlapConflict, events);
            ++stats_.overlap_conflicts;
        }
        while (stream.contiguous < config_.stream_bytes &&
               present_at(stream.present.get(), stream.contiguous)) {
            ++stream.contiguous;
        }
        const auto visible_end =
            std::min(allowed_end, static_cast<std::int64_t>(stream.contiguous));
        if (visible_end > start) {
            accepted =
                ByteRange{static_cast<std::size_t>(start), static_cast<std::size_t>(visible_end)};
        }
    }
    if (fin) {
        stream.fin_offset = end;
    }
}

ReassemblyUpdate TcpReassembler::observe(const FlowObservation& flow, const ParsedPacket& packet) {
    const auto tcp = validate_observation(flow, packet);
    const auto id = flow.flow.flow_id;
    auto found = flows_.find(id);
    if (found != flows_.end() && (found->second.key != flow.flow.key ||
                                  found->second.first_source != flow.flow.first_source)) {
        throw std::invalid_argument("A TCP flow ID cannot change endpoints.");
    }
    if (found == flows_.end()) {
        const bool retired = id <= highest_id_;
        highest_id_ = std::max(highest_id_, id);
        if (retired || flows_.size() >= config_.max_flows) {
            ReassemblyUpdate rejected;
            rejected.flow_id = id;
            rejected.direction = flow.direction;
            rejected.issues.set(static_cast<std::size_t>(ReassemblyIssue::CapacityLimit));
            rejected.events = rejected.issues;
            ++stats_.rejected;
            return rejected;
        }
        auto inserted = flows_.try_emplace(id);
        found = inserted.first;
        found->second.key = flow.flow.key;
        found->second.first_source = flow.flow.first_source;
    }
    auto& entry = found->second;
    auto& stream = entry.streams[flow.direction == FlowDirection::Forward ? 0U : 1U];
    stream.seen = true;
    const auto old_contiguous = stream.contiguous;
    const bool old_gap = gap_pending(stream);
    ReassemblyIssues events;
    std::optional<ByteRange> accepted;
    const auto flags = tcp.flags;
    if ((flags & 0x02U) != 0 && (flags & 0x05U) != 0) {
        note(stream, ReassemblyIssue::InvalidSegment, events);
    } else if (entry.reset || (flags & 0x04U) != 0) {
        entry.reset = true;
        for (auto& direction : entry.streams) {
            if (gap_pending(direction)) {
                direction.issues.set(static_cast<std::size_t>(ReassemblyIssue::Gap));
            }
            direction.issues.set(static_cast<std::size_t>(ReassemblyIssue::Reset));
            direction.disabled = true;
            release(direction);
        }
        events.set(static_cast<std::size_t>(ReassemblyIssue::Reset));
    } else {
        process(stream, packet, tcp, events, accepted);
    }
    auto result = snapshot(id, flow.direction, stream);
    if (!entry.reset && stream.contiguous > old_contiguous) {
        result.newly_contiguous = result.contiguous_prefix.subspan(old_contiguous);
        stats_.bytes_emitted += result.newly_contiguous.size();
    }
    const bool new_gap = gap_pending(stream);
    if (!entry.reset && old_gap != new_gap) {
        events.set(static_cast<std::size_t>(new_gap ? ReassemblyIssue::GapPending
                                                    : ReassemblyIssue::GapFilled));
    }
    result.events = events;
    result.payload_range = accepted;
    return result;
}

void TcpReassembler::remove(std::unordered_map<std::uint64_t, Entry>::iterator position) noexcept {
    for (auto& stream : position->second.streams) {
        release(stream);
    }
    flows_.erase(position);
}

void TcpReassembler::finish_flow(std::uint64_t flow_id, ReassemblyEnd reason,
                                 const ReassemblyEventSink& sink) {
    if (reason != ReassemblyEnd::IdleTimeout && reason != ReassemblyEnd::CaptureEnd) {
        throw std::invalid_argument("Unknown reassembly end reason.");
    }
    const auto found = flows_.find(flow_id);
    if (found == flows_.end()) {
        return;
    }
    try {
        for (std::size_t index = 0; index < found->second.streams.size(); ++index) {
            auto& stream = found->second.streams[index];
            if (!stream.seen) {
                continue;
            }
            auto update = snapshot(
                flow_id, index == 0 ? FlowDirection::Forward : FlowDirection::Backward, stream);
            if (gap_pending(stream)) {
                update.issues.set(static_cast<std::size_t>(ReassemblyIssue::Gap));
            }
            if (!update.closed) {
                update.issues.set(static_cast<std::size_t>(reason == ReassemblyEnd::IdleTimeout
                                                               ? ReassemblyIssue::IdleTimeout
                                                               : ReassemblyIssue::CaptureEnd));
            }
            update.end = reason;
            if (sink) {
                sink(update);
            }
        }
    } catch (...) {
        remove(found);
        throw;
    }
    remove(found);
}

void TcpReassembler::finish_all(ReassemblyEnd reason, const ReassemblyEventSink& sink) {
    try {
        while (!flows_.empty()) {
            finish_flow(flows_.begin()->first, reason, sink);
        }
    } catch (...) {
        while (!flows_.empty()) {
            remove(flows_.begin());
        }
        throw;
    }
}

TcpReassemblyStats TcpReassembler::stats() const noexcept {
    auto result = stats_;
    result.active_flows = flows_.size();
    return result;
}

}  // namespace miniips
