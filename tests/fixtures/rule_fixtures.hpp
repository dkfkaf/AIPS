#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <variant>
#include <vector>

#include "miniips/flow_table.hpp"
#include "miniips/rule_engine.hpp"
#include "miniips/rule_loader.hpp"

namespace miniips::test {

inline nlohmann::json test_rule(std::uint32_t sid = 1) {
    return {{"sid", sid},        {"enabled", true},   {"priority", 100},    {"action", "drop"},
            {"protocol", "tcp"}, {"scope", "stream"}, {"content", "HELLO"}, {"message", "Demo"}};
}

struct RuleSegment {
    std::uint32_t seq{};
    std::string_view data{};
    std::uint8_t flags{0x18};
    bool backward{};
    std::uint16_t client_port{12345};
    TransportProtocol protocol{TransportProtocol::Tcp};
    std::chrono::microseconds at{};
};

class RuleHarness {
   public:
    explicit RuleHarness(nlohmann::json rules, RuleEngineConfig config = {},
                         TcpReassemblyConfig tcp_config = {})
        : reassembler(tcp_config),
          engine(load_rules(nlohmann::json{{"rules", rules}}.dump()), config) {}

    DetectionDecision send(RuleSegment segment) {
        storage.clear();
        for (const char value : segment.data) {
            storage.push_back(static_cast<std::byte>(value));
        }
        packet = {};
        packet.captured_at = segment.at;
        packet.src_ip = segment.backward ? 0xC6336402U : 0xC0000201U;
        packet.dst_ip = segment.backward ? 0xC0000201U : 0xC6336402U;
        packet.src_port = segment.backward ? 8080 : segment.client_port;
        packet.dst_port = segment.backward ? segment.client_port : 8080;
        packet.protocol = segment.protocol;
        packet.ip_header_bytes = 20;
        packet.transport_header_bytes = segment.protocol == TransportProtocol::Tcp ? 20U : 8U;
        packet.ip_total_length = static_cast<std::uint16_t>(
            packet.ip_header_bytes + packet.transport_header_bytes + storage.size());
        packet.payload = storage;
        if (segment.protocol == TransportProtocol::Tcp) {
            packet.tcp = TcpMetadata{segment.seq, 0, segment.flags};
        }
        observation = std::get<FlowObservation>(flows.observe(packet, [&](const FlowSnapshot& old) {
            engine.forget_flow(old.flow_id);
            reassembler.finish_flow(old.flow_id, ReassemblyEnd::IdleTimeout, {});
        }));
        update.reset();
        if (segment.protocol == TransportProtocol::Tcp) {
            update = reassembler.observe(*observation, packet);
        }
        return engine.evaluate(packet, &*observation, update ? &*update : nullptr);
    }

    const ReassemblyUpdate& stream_update() const {
        if (!update) {
            throw std::logic_error("Test requires a TCP update.");
        }
        return *update;
    }
    const FlowObservation& tracked_flow() const {
        if (!observation) {
            throw std::logic_error("Test requires a tracked flow.");
        }
        return *observation;
    }

    FlowTable flows;
    TcpReassembler reassembler;
    RuleEngine engine;
    std::vector<std::byte> storage;
    ParsedPacket packet;
    std::optional<FlowObservation> observation;
    std::optional<ReassemblyUpdate> update;
};

}  // namespace miniips::test
