#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <nlohmann/json.hpp>
#include <optional>
#include <stdexcept>
#include <vector>

#include "fixtures/reassembly_fixtures.hpp"
#include "miniips/engine.hpp"
#include "miniips/rule_loader.hpp"

namespace miniips {
namespace {

template <typename T>
const T& required(const std::optional<T>& value) {
    if (!value) {
        throw std::logic_error("Expected Engine result metadata is absent.");
    }
    return *value;
}

RuleSet drop_rules(bool packet_scope = false) {
    auto rule = nlohmann::json{{"sid", 1},           {"enabled", true},
                               {"priority", 100},    {"action", "drop"},
                               {"protocol", "tcp"},  {"scope", packet_scope ? "packet" : "stream"},
                               {"content", "HELLO"}, {"message", "Demo"}};
    return load_rules(nlohmann::json{{"rules", nlohmann::json::array({rule})}}.dump());
}

PacketResult inspect_bytes(Engine& engine, const std::vector<std::byte>& bytes,
                           std::chrono::microseconds at = {}) {
    return engine.inspect({bytes, static_cast<std::uint32_t>(bytes.size()), at});
}

TEST(Engine, ResultsOwnMetadataAfterInputStorageIsReused) {
    Engine engine;
    auto bytes = test::tcp_packet();
    const auto result = inspect_bytes(engine, bytes);
    bytes.assign(100, std::byte{'X'});
    ASSERT_TRUE(result.packet);
    EXPECT_EQ(required(result.packet).payload_bytes, 5);
    EXPECT_EQ(required(result.packet).src_ip, 0xC0000201U);
    ASSERT_TRUE(result.reassembly);
    EXPECT_EQ(required(result.reassembly).bytes, 5);
    EXPECT_FALSE(result.decision);
    EXPECT_FALSE(result.parse_error);
    EXPECT_EQ(result.packet_number, 1);
}

TEST(Engine, ParsesValidAndDamagedInputsAndFinalizesSortedFlows) {
    Engine engine;
    inspect_bytes(engine, test::tcp_packet());
    inspect_bytes(engine, test::udp_packet());
    const auto bad = inspect_bytes(engine, {std::byte{1}});
    EXPECT_EQ(bad.parse_error, ParseError::TruncatedEthernet);
    EXPECT_FALSE(bad.packet);
    EXPECT_FALSE(bad.decision);
    const auto final = engine.finish();
    EXPECT_TRUE(final.stats.capture_complete);
    EXPECT_EQ(final.stats.packets, 3);
    EXPECT_EQ(final.stats.parsed, 2);
    EXPECT_EQ(final.stats.skipped, 1);
    ASSERT_EQ(final.flows.size(), 2);
    EXPECT_EQ(final.flows[0].flow.flow_id, 1);
    EXPECT_EQ(final.flows[1].flow.flow_id, 2);
    EXPECT_EQ(final.stats.flow.active, 2);
    EXPECT_EQ(final.stats.tcp.memory_bytes, 0);
}

TEST(Engine, JoinsHelloRetainsRetransmitDropAndAllowsAck) {
    Engine engine({}, drop_rules());
    inspect_bytes(engine, test::tcp_segment({.sequence = 99, .flags = 0x02}));
    auto hello = inspect_bytes(engine, test::tcp_segment({.sequence = 100, .payload = "HEL"}));
    ASSERT_TRUE(hello.decision);
    EXPECT_EQ(required(hello.decision).action, DetectionAction::Allow);
    auto joined = inspect_bytes(engine, test::tcp_segment({.sequence = 103, .payload = "LO"}));
    ASSERT_TRUE(joined.decision);
    EXPECT_EQ(required(joined.decision).action, DetectionAction::Drop);
    EXPECT_EQ(required(joined.decision).matches.size(), 1);
    auto duplicate = inspect_bytes(engine, test::tcp_segment({.sequence = 100, .payload = "HEL"}));
    ASSERT_TRUE(duplicate.decision);
    EXPECT_EQ(required(duplicate.decision).action, DetectionAction::Drop);
    EXPECT_EQ(required(duplicate.decision).suppressed, 1);
    auto ack = inspect_bytes(engine, test::tcp_segment({.sequence = 105, .flags = 0x10}));
    ASSERT_TRUE(ack.decision);
    EXPECT_EQ(required(ack.decision).action, DetectionAction::Allow);
    const auto final = engine.finish();
    EXPECT_EQ(final.stats.detections, 1);
    EXPECT_EQ(final.stats.rules.events_emitted, 1);
    EXPECT_EQ(final.stats.rules.suppressed, 1);
    EXPECT_EQ(final.stats.rules.drops, 2);
    EXPECT_EQ(final.stats.rules.state_bytes, 0);
    EXPECT_EQ(final.stats.tcp.memory_bytes, 0);
}

TEST(Engine, BothDirectionsShareIdAndKeepSeparateStreamSummaries) {
    Engine engine;
    auto forward = inspect_bytes(engine, test::tcp_packet());
    auto backward = inspect_bytes(engine, test::reverse_tcp_packet());
    ASSERT_TRUE(forward.flow);
    ASSERT_TRUE(backward.flow);
    EXPECT_EQ(std::get<FlowObservation>(required(forward.flow)).flow.flow_id, 1);
    EXPECT_EQ(std::get<FlowObservation>(required(backward.flow)).direction,
              FlowDirection::Backward);
    const auto final = engine.finish();
    ASSERT_EQ(final.flows.size(), 1);
    const auto& ended = final.flows[0];
    ASSERT_TRUE(ended.streams[0]);
    ASSERT_TRUE(ended.streams[1]);
    EXPECT_EQ(required(ended.streams[0]).bytes, 5);
    EXPECT_EQ(required(ended.streams[1]).bytes, 5);
    EXPECT_EQ(ended.flow.fwd.packets, 1);
    EXPECT_EQ(ended.flow.bwd.packets, 1);
}

TEST(Engine, DamagedFrameExpiresFlowAndReleasesRuleBudget) {
    Engine engine({.flows = {}, .rule_state_bytes = 8}, drop_rules());
    inspect_bytes(engine, test::tcp_packet());
    const auto bad = inspect_bytes(engine, {std::byte{1}}, std::chrono::seconds{120});
    ASSERT_EQ(bad.expired.size(), 1);
    EXPECT_EQ(bad.expired[0].reason, FlowEndReason::Expired);
    EXPECT_EQ(bad.expired[0].flow.flow_id, 1);
    EXPECT_EQ(bad.expired[0].flow.first_source, (FlowEndpoint{0xC0000201U, 12345}));
    EXPECT_EQ(engine.stats().rules.state_bytes, 0);
    auto next = inspect_bytes(engine, test::tcp_packet(), std::chrono::seconds{121});
    ASSERT_TRUE(next.decision);
    EXPECT_EQ(required(next.decision).matches.size(), 1);
    ASSERT_TRUE(next.flow);
    EXPECT_EQ(std::get<FlowObservation>(required(next.flow)).flow.flow_id, 2);
}

TEST(Engine, CapacityFailureStillEvaluatesPacketRules) {
    Engine engine({.flows = {.max_entries = 1}}, drop_rules(true));
    inspect_bytes(engine, test::udp_packet());
    auto result = inspect_bytes(engine, test::tcp_packet());
    ASSERT_TRUE(result.flow);
    EXPECT_TRUE(std::holds_alternative<FlowError>(required(result.flow)));
    EXPECT_FALSE(result.reassembly);
    ASSERT_TRUE(result.decision);
    EXPECT_EQ(required(result.decision).action, DetectionAction::Drop);
    EXPECT_EQ(engine.stats().flow.rejected, 1);
}

TEST(Engine, EmptyAbortAndFinishAreIdempotent) {
    Engine engine;
    const auto empty = engine.finish(EngineEnd::Aborted);
    EXPECT_FALSE(empty.stats.capture_complete);
    EXPECT_FALSE(empty.stats.watermark);
    EXPECT_TRUE(empty.flows.empty());
    const auto repeated = engine.finish();
    EXPECT_FALSE(repeated.stats.capture_complete);
    EXPECT_TRUE(repeated.flows.empty());
    EXPECT_THROW(inspect_bytes(engine, test::tcp_packet()), std::logic_error);
}

TEST(Engine, EofDoesNotRepeatFlowEventsOrIncompleteCounters) {
    Engine engine;
    inspect_bytes(engine, test::tcp_packet());
    const auto first = engine.finish();
    const auto second = engine.finish();
    EXPECT_EQ(first.flows.size(), 1);
    EXPECT_TRUE(second.flows.empty());
    EXPECT_EQ(first.stats.incomplete_directions, second.stats.incomplete_directions);
}

TEST(Engine, BackwardsTimestampsPreserveWatermarkAndRealFlowTimes) {
    Engine engine;
    inspect_bytes(engine, test::tcp_packet(), std::chrono::seconds{100});
    inspect_bytes(engine, test::tcp_packet(), std::chrono::seconds{99});
    const auto final = engine.finish();
    EXPECT_EQ(final.stats.watermark, std::chrono::seconds{100});
    ASSERT_EQ(final.flows.size(), 1);
    EXPECT_EQ(final.flows[0].flow.first_seen, std::chrono::seconds{99});
    EXPECT_EQ(final.flows[0].flow.last_seen, std::chrono::seconds{100});
}

TEST(Engine, ProcessingBudgetFailureNeverBecomesDefaultAllow) {
    Engine engine({.flows = {}, .rule_state_bytes = 7}, drop_rules());
    const auto failed = inspect_bytes(engine, test::tcp_packet());
    EXPECT_TRUE(failed.processing_error);
    EXPECT_FALSE(failed.decision);
    EXPECT_EQ(engine.stats().processing_errors, 1);
    EXPECT_EQ(engine.stats().parsed, 1);
    EXPECT_THROW(inspect_bytes(engine, test::tcp_packet()), std::logic_error);
    const auto final = engine.finish();
    EXPECT_FALSE(final.stats.capture_complete);
    EXPECT_EQ(final.stats.tcp.memory_bytes, 0);
}

TEST(Engine, RejectsNegativeTimeAndInvalidConfiguration) {
    Engine engine;
    EXPECT_THROW(inspect_bytes(engine, test::tcp_packet(), std::chrono::microseconds{-1}),
                 std::invalid_argument);
    EXPECT_EQ(engine.stats().packets, 0);
    EXPECT_THROW((Engine{EngineConfig{.flows = {.max_entries = 0}}}), std::invalid_argument);
    EngineConfig invalid;
    invalid.rule_state_bytes = 0;
    EXPECT_THROW((Engine{invalid}), std::invalid_argument);
}

}  // namespace
}  // namespace miniips
