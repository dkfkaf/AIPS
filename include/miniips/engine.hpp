#pragma once

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "miniips/flow_table.hpp"
#include "miniips/packet_parser.hpp"
#include "miniips/rule_engine.hpp"

namespace miniips {

// Owned packet metadata; deliberately contains no capture/payload span.
struct PacketMetadata {
    std::chrono::microseconds captured_at{};
    std::uint32_t src_ip{}, dst_ip{};
    std::uint16_t src_port{}, dst_port{}, ip_total_length{};
    std::size_t ip_header_bytes{}, transport_header_bytes{}, payload_bytes{};
    TransportProtocol protocol{TransportProtocol::Tcp};
    std::optional<TcpMetadata> tcp;
};
struct StreamSummary {
    std::uint64_t flow_id{};
    FlowDirection direction{FlowDirection::Forward};
    std::size_t bytes{}, new_bytes{}, pending_bytes{};
    ReassemblyIssues issues, events;
    bool fin_seen{}, closed{};
    std::optional<ReassemblyEnd> end;
};
enum class FlowEndReason : std::uint8_t { Expired, Eof, Aborted };
struct FlowEnd {
    FlowSnapshot flow;
    FlowEndReason reason{FlowEndReason::Eof};
    std::array<std::optional<StreamSummary>, 2> streams;
};
struct ProcessingError {
    std::string domain;
    std::string reason;
    std::string message;
};
struct PacketResult {
    std::uint64_t packet_number{};
    std::chrono::microseconds captured_at{};
    std::size_t captured_bytes{};
    std::chrono::microseconds watermark{};
    std::uint32_t original_bytes{};
    bool rules_enabled{};
    std::optional<PacketMetadata> packet;
    std::optional<FlowResult> flow;
    std::optional<StreamSummary> reassembly;
    std::optional<DetectionDecision> decision;
    std::optional<ParseError> parse_error;
    std::optional<ProcessingError> processing_error;
    std::vector<FlowEnd> expired;
};
enum class EngineEnd : std::uint8_t { Eof, Aborted };
struct EngineStats {
    std::uint64_t packets{}, parsed{}, skipped{}, processing_errors{};
    std::uint64_t detections{}, incomplete_directions{};
    FlowTableStats flow;
    TcpReassemblyStats tcp;
    RuleEngineStats rules;
    std::optional<std::chrono::microseconds> watermark;
    bool rules_enabled{}, capture_complete{};
};
struct FinishResult {
    EngineEnd reason{EngineEnd::Eof};
    EngineStats stats;
    std::vector<FlowEnd> flows;
};
struct EngineConfig {
    FlowTableConfig flows;
    std::size_t tcp_stream_bytes{65536};
    std::size_t tcp_memory_bytes{134217728};
    std::size_t rule_state_bytes{33554432};
};

// Single-threaded and sink-free. Consume/publish/discard one owned result at a
// time. Counts bound lifecycle batches; no per-capture event queue is retained.
class Engine {
   public:
    explicit Engine(EngineConfig config = {}, std::optional<RuleSet> rules = std::nullopt);
    Engine(const Engine&) = delete;
    Engine& operator=(const Engine&) = delete;
    PacketResult inspect(const PacketEnvelope& envelope);
    FinishResult finish(EngineEnd reason = EngineEnd::Eof);
    EngineStats stats() const noexcept;

   private:
    void collect_end(const FlowSnapshot& flow, FlowEndReason reason, std::vector<FlowEnd>& records);
    FlowTable flows_;
    TcpReassembler reassembler_;
    std::optional<RuleEngine> detector_;
    EngineStats counters_;
    bool finished_{}, processing_failed_{};
    EngineEnd end_reason_{EngineEnd::Eof};
};

}  // namespace miniips
