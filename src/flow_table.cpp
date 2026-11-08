#include "miniips/flow_table.hpp"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <limits>
#include <optional>
#include <stdexcept>
#include <utility>

namespace miniips {
namespace {

std::uint64_t checked_add(std::uint64_t value, std::uint64_t amount) {
    if (amount > std::numeric_limits<std::uint64_t>::max() - value) {
        throw std::overflow_error("Flow counter or identifier overflow.");
    }
    return value + amount;
}

void validate_packet(const ParsedPacket& packet) {
    const bool tcp = packet.protocol == TransportProtocol::Tcp;
    const bool udp = packet.protocol == TransportProtocol::Udp;
    if (packet.captured_at.count() < 0 || (!tcp && !udp) || tcp != packet.tcp.has_value() ||
        packet.ip_total_length < (tcp ? 40U : 28U)) {
        throw std::invalid_argument("Flow tracking requires valid IPv4 TCP/UDP metadata.");
    }
}

void update_direction(FlowDirectionStats& stats, const ParsedPacket& packet) {
    stats.packets = checked_add(stats.packets, 1);
    stats.bytes = checked_add(stats.bytes, packet.ip_total_length);
    if (stats.last_seen) {
        const auto delta = packet.captured_at >= *stats.last_seen
                               ? packet.captured_at - *stats.last_seen
                               : std::chrono::microseconds{0};
        stats.iat_sum_us = checked_add(stats.iat_sum_us, static_cast<std::uint64_t>(delta.count()));
        stats.iat_samples = checked_add(stats.iat_samples, 1);
        stats.last_seen = std::max(*stats.last_seen, packet.captured_at);
    } else {
        stats.last_seen = packet.captured_at;
    }
    if (packet.tcp) {
        const auto flags = packet.tcp->flags;
        stats.syn_count = checked_add(stats.syn_count, (flags & 0x02U) != 0 ? 1U : 0U);
        stats.ack_count = checked_add(stats.ack_count, (flags & 0x10U) != 0 ? 1U : 0U);
        stats.fin_count = checked_add(stats.fin_count, (flags & 0x01U) != 0 ? 1U : 0U);
        stats.rst_count = checked_add(stats.rst_count, (flags & 0x04U) != 0 ? 1U : 0U);
        stats.psh_count = checked_add(stats.psh_count, (flags & 0x08U) != 0 ? 1U : 0U);
    }
}

void mix_hash(std::size_t& seed, std::size_t value) noexcept {
    constexpr auto HASH_SALT = static_cast<std::size_t>(0x9E3779B97F4A7C15ULL);
    seed ^= value + HASH_SALT + (seed << 6U) + (seed >> 2U);
}

}  // namespace

std::size_t FlowKeyHash::operator()(const FlowKey& key) const noexcept {
    std::size_t seed = 0;
    mix_hash(seed, std::hash<std::uint32_t>{}(key.low.ip));
    mix_hash(seed, std::hash<std::uint16_t>{}(key.low.port));
    mix_hash(seed, std::hash<std::uint32_t>{}(key.high.ip));
    mix_hash(seed, std::hash<std::uint16_t>{}(key.high.port));
    mix_hash(seed, std::hash<std::uint8_t>{}(static_cast<std::uint8_t>(key.protocol)));
    return seed;
}

FlowKey make_flow_key(const ParsedPacket& packet) {
    FlowEndpoint source{packet.src_ip, packet.src_port};
    FlowEndpoint destination{packet.dst_ip, packet.dst_port};
    if (destination < source) {
        std::swap(source, destination);
    }
    return {source, destination, packet.protocol};
}

FlowTable::FlowTable(FlowTableConfig config) : config_(config) {
    if (config_.max_entries == 0 || config_.idle_timeout.count() <= 0) {
        throw std::invalid_argument("Flow capacity and idle timeout must be positive.");
    }
}

std::size_t FlowTable::expire(std::chrono::microseconds now, const FlowExpirySink& on_expire) {
    if (now.count() < 0) {
        throw std::invalid_argument("Flow expiration time cannot be negative.");
    }
    watermark_ = std::max(watermark_, now);
    std::size_t removed = 0;
    for (auto position = flows_.begin(); position != flows_.end();) {
        if (watermark_ - position->second.last_activity >= config_.idle_timeout) {
            if (on_expire) {
                on_expire(position->second.snapshot);
            }
            position = flows_.erase(position);
            ++removed;
            // Count immediately so a later callback exception cannot hide erasures.
            ++expired_;
        } else {
            ++position;
        }
    }
    return removed;
}

FlowResult FlowTable::observe(const ParsedPacket& packet, const FlowExpirySink& on_expire) {
    validate_packet(packet);
    expire(packet.captured_at, on_expire);
    const auto key = make_flow_key(packet);
    const auto position = flows_.find(key);
    const FlowEndpoint source{packet.src_ip, packet.src_port};
    if (position != flows_.end()) {
        Entry updated = position->second;
        const auto direction = source == updated.snapshot.first_source ? FlowDirection::Forward
                                                                       : FlowDirection::Backward;
        update_entry(updated, packet, direction);
        updated.last_activity = watermark_;
        position->second = updated;
        return FlowObservation{updated.snapshot, direction, false};
    }
    if (flows_.size() >= config_.max_entries) {
        rejected_ = checked_add(rejected_, 1);
        return FlowError::CapacityExceeded;
    }

    Entry entry;
    entry.snapshot.flow_id = checked_add(created_, 1);
    entry.snapshot.key = key;
    entry.snapshot.first_source = source;
    entry.snapshot.first_seen = packet.captured_at;
    entry.snapshot.last_seen = packet.captured_at;
    if (packet.protocol == TransportProtocol::Tcp) {
        entry.snapshot.tcp_state = TcpFlowState::Observed;
    }
    entry.last_activity = watermark_;
    update_entry(entry, packet, FlowDirection::Forward);
    flows_.emplace(key, entry);
    created_ = entry.snapshot.flow_id;
    return FlowObservation{entry.snapshot, FlowDirection::Forward, true};
}

void FlowTable::update_entry(Entry& entry, const ParsedPacket& packet, FlowDirection direction) {
    auto& flow = entry.snapshot;
    auto& stats = direction == FlowDirection::Forward ? flow.fwd : flow.bwd;
    update_direction(stats, packet);
    flow.first_seen = std::min(flow.first_seen, packet.captured_at);
    flow.last_seen = std::max(flow.last_seen, packet.captured_at);
    update_tcp_state(entry, packet, direction);
}

void FlowTable::update_tcp_state(Entry& entry, const ParsedPacket& packet,
                                 FlowDirection direction) {
    if (!entry.snapshot.tcp_state || !packet.tcp) {
        return;
    }
    auto& state = *entry.snapshot.tcp_state;
    const auto flags = packet.tcp->flags;
    if (state == TcpFlowState::Reset) {
        return;
    }
    if ((flags & 0x04U) != 0) {
        state = TcpFlowState::Reset;
        return;
    }
    if ((flags & 0x01U) != 0) {
        if (direction == FlowDirection::Forward) {
            entry.forward_fin = true;
        } else {
            entry.backward_fin = true;
        }
        state =
            entry.forward_fin && entry.backward_fin ? TcpFlowState::Closed : TcpFlowState::Closing;
        return;
    }
    if (state == TcpFlowState::Closing || state == TcpFlowState::Closed ||
        state == TcpFlowState::Established) {
        return;
    }
    const bool syn = (flags & 0x02U) != 0;
    const bool ack = (flags & 0x10U) != 0;
    if (syn) {
        state = TcpFlowState::SynSeen;
        if (!ack && !entry.syn_initiator) {
            entry.syn_initiator = direction;
        } else if (ack && entry.syn_initiator && direction != *entry.syn_initiator) {
            entry.syn_ack_seen = true;
        }
    } else if (ack && entry.syn_ack_seen && entry.syn_initiator &&
               direction == *entry.syn_initiator) {
        state = TcpFlowState::Established;
    }
}

std::optional<FlowSnapshot> FlowTable::find(const FlowKey& key) const {
    const auto position = flows_.find(key);
    if (position == flows_.end()) {
        return std::nullopt;
    }
    return position->second.snapshot;
}

void FlowTable::visit(const FlowExpirySink& visitor) const {
    if (visitor) {
        for (const auto& [key, entry] : flows_) {
            static_cast<void>(key);
            visitor(entry.snapshot);
        }
    }
}

FlowTableStats FlowTable::stats() const noexcept {
    return {created_, expired_, rejected_, flows_.size()};
}

std::size_t FlowTable::size() const noexcept { return flows_.size(); }

}  // namespace miniips
