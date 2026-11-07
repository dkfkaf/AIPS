#include "miniips/rule_engine.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <stdexcept>
#include <utility>

namespace miniips {
namespace {

void validate_input(const ParsedPacket& packet, const FlowObservation* flow,
                    const ReassemblyUpdate* stream) {
    const bool tcp = packet.protocol == TransportProtocol::Tcp;
    const bool udp = packet.protocol == TransportProtocol::Udp;
    const auto transport_minimum = tcp ? 20U : 8U;
    if ((!tcp && !udp) || packet.captured_at.count() < 0 || tcp != packet.tcp.has_value() ||
        packet.ip_header_bytes < 20 || packet.ip_header_bytes > 60 ||
        packet.ip_header_bytes % 4 != 0 || packet.transport_header_bytes < transport_minimum ||
        packet.transport_header_bytes > (tcp ? 60U : 8U) ||
        packet.transport_header_bytes % 4 != 0) {
        throw std::invalid_argument("Invalid parsed packet for rule inspection.");
    }
    const auto headers = packet.ip_header_bytes + packet.transport_header_bytes;
    if (headers > packet.ip_total_length ||
        packet.payload.size() != packet.ip_total_length - headers) {
        throw std::invalid_argument("Inconsistent payload length for rule inspection.");
    }
    if (flow) {
        const auto direction =
            FlowEndpoint{packet.src_ip, packet.src_port} == flow->flow.first_source
                ? FlowDirection::Forward
                : FlowDirection::Backward;
        if (flow->flow.flow_id == 0 || flow->flow.key != make_flow_key(packet) ||
            (flow->flow.first_source != flow->flow.key.low &&
             flow->flow.first_source != flow->flow.key.high) ||
            flow->direction != direction) {
            throw std::invalid_argument("Inconsistent flow context for rules.");
        }
    }
    if (stream) {
        if (!tcp || !flow || stream->flow_id != flow->flow.flow_id ||
            stream->direction != flow->direction || stream->end ||
            stream->contiguous_prefix.size() >= 0x80000000ULL ||
            stream->newly_contiguous.size() > stream->contiguous_prefix.size()) {
            throw std::invalid_argument("Inconsistent reassembly context for rules.");
        }
        const auto prefix = stream->contiguous_prefix;
        if ((!stream->newly_contiguous.empty() &&
             stream->newly_contiguous.data() !=
                 prefix.subspan(prefix.size() - stream->newly_contiguous.size()).data()) ||
            (stream->payload_range && (stream->payload_range->begin >= stream->payload_range->end ||
                                       stream->payload_range->end > prefix.size()))) {
            throw std::invalid_argument("Invalid related prefix range for rules.");
        }
        const auto accepted = stream->payload_range;
        const auto added = stream->newly_contiguous.size();
        const auto first_new = prefix.size() - added;
        if ((packet.payload.empty() && (accepted || added != 0)) ||
            (accepted && accepted->end - accepted->begin > packet.payload.size()) ||
            (added != 0 &&
             (!accepted || accepted->begin > first_new || accepted->end <= first_new)) ||
            ((has_issue(stream->issues, ReassemblyIssue::Reset) ||
              has_issue(stream->issues, ReassemblyIssue::SessionReuse) ||
              has_issue(stream->issues, ReassemblyIssue::MemoryLimit)) &&
             (accepted || added != 0))) {
            throw std::invalid_argument("Reassembly ranges cannot be produced by this payload.");
        }
    }
}

bool header_matches(const Rule& rule, const ParsedPacket& packet) {
    return (rule.protocol == RuleProtocol::Any ||
            (rule.protocol == RuleProtocol::Tcp && packet.protocol == TransportProtocol::Tcp) ||
            (rule.protocol == RuleProtocol::Udp && packet.protocol == TransportProtocol::Udp)) &&
           (!rule.src_port || *rule.src_port == packet.src_port) &&
           (!rule.dst_port || *rule.dst_port == packet.dst_port);
}

// Search bounded context but report only matches intersecting the related range.
std::optional<std::size_t> last_match(const Rule& rule, std::span<const std::byte> bytes,
                                      ByteRange related) {
    if (related.begin == related.end) {
        return std::nullopt;
    }
    const auto context = rule.content.size() - 1;
    const auto begin = related.begin - std::min(related.begin, context);
    const auto end = related.end + std::min(bytes.size() - related.end, context);
    std::size_t matched = 0;
    std::optional<std::size_t> last;
    for (auto index = begin; index < end; ++index) {
        const auto byte = std::to_integer<unsigned char>(bytes[index]);
        while (matched != 0 && byte != static_cast<unsigned char>(rule.content[matched])) {
            matched = rule.failure[matched - 1];
        }
        if (byte == static_cast<unsigned char>(rule.content[matched])) {
            ++matched;
        }
        if (matched == rule.content.size()) {
            const auto match_end = index + 1;
            const auto match_begin = match_end - matched;
            if (match_begin < related.end && match_end > related.begin) {
                last = match_end;
            }
            matched = rule.failure[matched - 1];
        }
    }
    return last;
}

}  // namespace

RuleEngine::RuleEngine(RuleSet rules, RuleEngineConfig config)
    : rules_(std::move(rules)), config_(config) {
    if (config_.max_flows == 0 || config_.state_bytes == 0) {
        throw std::invalid_argument("Rule state capacity and memory must be positive.");
    }
}

std::uint64_t* RuleEngine::watermark(Entry& entry, FlowDirection direction) {
    auto& array = entry.ends[direction == FlowDirection::Forward ? 0U : 1U];
    if (!array) {
        const auto cost = rules_.stream_rule_count() * sizeof(std::uint64_t);
        if (cost > config_.state_bytes - stats_.state_bytes) {
            throw DetectionError("Stream rule watermark memory limit exceeded.");
        }
        array = std::make_unique<std::uint64_t[]>(rules_.stream_rule_count());
        stats_.state_bytes += cost;
        stats_.peak_state_bytes = std::max(stats_.peak_state_bytes, stats_.state_bytes);
    }
    return array.get();
}

DetectionDecision RuleEngine::evaluate(const ParsedPacket& packet, const FlowObservation* flow,
                                       const ReassemblyUpdate* stream) {
    validate_input(packet, flow, stream);
    Entry* entry = nullptr;
    if (flow && packet.protocol == TransportProtocol::Tcp && rules_.stream_rule_count() != 0) {
        const auto id = flow->flow.flow_id;
        auto found = flows_.find(id);
        if (found == flows_.end()) {
            if (id <= highest_id_ || flows_.size() >= config_.max_flows) {
                throw DetectionError("Stream rule flow capacity or retired ID violation.");
            }
            found = flows_.try_emplace(id).first;
            found->second.key = flow->flow.key;
            found->second.first_source = flow->flow.first_source;
            highest_id_ = id;
        } else if (found->second.key != flow->flow.key ||
                   found->second.first_source != flow->flow.first_source) {
            throw std::invalid_argument("Rule flow ID cannot change endpoints.");
        }
        entry = &found->second;
    }
    std::array<std::optional<ByteRange>, 2> ranges;
    if (stream) {
        ranges[0] = stream->payload_range;
        if (!stream->newly_contiguous.empty()) {
            ranges[1] =
                ByteRange{stream->contiguous_prefix.size() - stream->newly_contiguous.size(),
                          stream->contiguous_prefix.size()};
        }
    }
    DetectionDecision decision;
    decision.stream_evaluated = stream && rules_.stream_rule_count() != 0 &&
                                (ranges[0].has_value() || ranges[1].has_value());
    for (const auto& rule : rules_.rules()) {
        if (!rule.enabled || !header_matches(rule, packet)) {
            continue;
        }
        // Content is nonempty, so zero is an unambiguous no-match end offset.
        std::size_t end = 0;
        if (rule.scope == RuleScope::Packet) {
            end = last_match(rule, packet.payload, {0, packet.payload.size()}).value_or(0);
        } else if (decision.stream_evaluated && stream) {
            for (const auto& range : ranges) {
                if (range) {
                    const auto candidate = last_match(rule, stream->contiguous_prefix, *range);
                    end = std::max(end, candidate.value_or(0));
                }
            }
        }
        if (end == 0) {
            continue;
        }
        bool emit = true;
        if (rule.scope == RuleScope::Stream) {
            if (!entry || !flow) {
                throw std::logic_error("Missing validated stream rule state.");
            }
            auto& previous = watermark(*entry, flow->direction)[rule.stream_index];
            emit = end > previous;
            if (emit) {
                previous = end;
            }
        }
        if (emit) {
            decision.matches.push_back({rule.sid, rule.action, rule.scope, end, rule.message});
        } else {
            ++decision.suppressed;
        }
        if (rule.action != RuleAction::Alert) {
            decision.terminal_sid = rule.sid;
            decision.action =
                rule.action == RuleAction::Drop ? DetectionAction::Drop : DetectionAction::Allow;
            break;
        }
    }
    ++stats_.packets_evaluated;
    stats_.events_emitted += decision.matches.size();
    stats_.suppressed += decision.suppressed;
    stats_.drops += decision.action == DetectionAction::Drop ? 1U : 0U;
    return decision;
}

void RuleEngine::forget_flow(std::uint64_t id) noexcept {
    const auto found = flows_.find(id);
    if (found != flows_.end()) {
        for (const auto& array : found->second.ends) {
            if (array) {
                stats_.state_bytes -= rules_.stream_rule_count() * sizeof(std::uint64_t);
            }
        }
        flows_.erase(found);
    }
}

void RuleEngine::clear() noexcept {
    flows_.clear();
    stats_.state_bytes = 0;
}

RuleEngineStats RuleEngine::stats() const noexcept {
    auto result = stats_;
    result.active_flows = flows_.size();
    return result;
}

}  // namespace miniips
