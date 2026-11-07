#include <gtest/gtest.h>

#include <chrono>
#include <stdexcept>
#include <string>

#include "fixtures/rule_fixtures.hpp"

namespace miniips {
namespace {
using Json = nlohmann::json;
using test::test_rule;

TEST(RuleEngine, StreamHelloCrossesPacketsAndDuplicateStillDrops) {
    test::RuleHarness h(Json::array({test_rule()}));
    h.send({.seq = 99, .flags = 0x02});
    EXPECT_EQ(h.send({.seq = 100, .data = "HEL"}).action, DetectionAction::Allow);
    auto decision = h.send({.seq = 103, .data = "LO"});
    ASSERT_EQ(decision.matches.size(), 1);
    EXPECT_EQ(decision.action, DetectionAction::Drop);
    EXPECT_EQ(decision.matches[0].end_offset, 5);
    EXPECT_EQ(decision.terminal_sid, 1);
    for (const auto segment :
         {test::RuleSegment{.seq = 100, .data = "HEL"}, test::RuleSegment{.seq = 103, .data = "LO"},
          test::RuleSegment{.seq = 100, .data = "HELLO"}}) {
        decision = h.send(segment);
        EXPECT_EQ(decision.action, DetectionAction::Drop);
        EXPECT_TRUE(decision.matches.empty());
        EXPECT_EQ(decision.suppressed, 1);
        EXPECT_EQ(decision.terminal_sid, 1);
    }
    EXPECT_EQ(h.send({.seq = 105, .flags = 0x10}).action, DetectionAction::Allow);
    EXPECT_EQ(h.send({.seq = 105, .data = "OTHER"}).action, DetectionAction::Allow);
}

TEST(RuleEngine, PacketRuleDoesNotJoinSegmentsAndIsNotStreamDeduplicated) {
    auto rule = test_rule();
    rule["scope"] = "packet";
    test::RuleHarness h(Json::array({rule}));
    EXPECT_TRUE(h.send({.seq = 100, .data = "HEL"}).matches.empty());
    EXPECT_TRUE(h.send({.seq = 103, .data = "LO"}).matches.empty());
    EXPECT_EQ(h.send({.seq = 200, .data = "HELLO"}).matches.size(), 1);
    EXPECT_EQ(h.send({.seq = 200, .data = "HELLO"}).matches.size(), 1);
    EXPECT_EQ(h.engine.stats().state_bytes, 0);
}

TEST(RuleEngine, AlertContinuesAndPassStopsLowerRulesWithoutStickyFlowPass) {
    auto alert = test_rule(1);
    alert["action"] = "alert";
    auto pass = test_rule(2);
    pass["action"] = "pass";
    auto drop = test_rule(3);
    test::RuleHarness h(Json::array({drop, pass, alert}));
    auto decision = h.send({.seq = 100, .data = "HELLO"});
    ASSERT_EQ(decision.matches.size(), 2);
    EXPECT_EQ(decision.matches[0].sid, 1);
    EXPECT_EQ(decision.matches[1].sid, 2);
    EXPECT_EQ(decision.action, DetectionAction::Allow);
    EXPECT_EQ(decision.terminal_sid, 2);
    decision = h.send({.seq = 100, .data = "HELLO"});
    EXPECT_EQ(decision.terminal_sid, 2);
    EXPECT_EQ(decision.suppressed, 2);
    EXPECT_TRUE(decision.matches.empty());
    decision = h.send({.seq = 105, .data = "OTHER"});
    EXPECT_FALSE(decision.terminal_sid);
}

TEST(RuleEngine, PriorityBeatsSidAndDisabledRulesDoNotFire) {
    auto pass = test_rule(1);
    pass["action"] = "pass";
    auto drop = test_rule(99);
    drop["priority"] = 0;
    auto disabled = drop;
    disabled["sid"] = 100;
    disabled["priority"] = -1;
    disabled["enabled"] = false;
    test::RuleHarness h(Json::array({pass, disabled, drop}));
    const auto decision = h.send({.seq = 1, .data = "HELLO"});
    EXPECT_EQ(decision.action, DetectionAction::Drop);
    EXPECT_EQ(decision.terminal_sid, 99);
    ASSERT_EQ(decision.matches.size(), 1);
    EXPECT_EQ(decision.matches[0].sid, 99);
}

TEST(RuleEngine, HeadersUseCurrentDirectionAndAnyPacketSupportsUdp) {
    auto rule = test_rule();
    rule["scope"] = "packet";
    rule["protocol"] = "any";
    rule["src_port"] = 12345;
    rule["dst_port"] = 8080;
    test::RuleHarness h(Json::array({rule}));
    EXPECT_EQ(h.send({.seq = 1, .data = "HELLO"}).action, DetectionAction::Drop);
    EXPECT_EQ(h.send({.seq = 1, .data = "HELLO", .backward = true}).action, DetectionAction::Allow);
    EXPECT_EQ(h.send({.seq = 1, .data = "hello"}).action, DetectionAction::Allow);
    EXPECT_EQ(h.send({.data = "HELLO", .protocol = TransportProtocol::Udp}).action,
              DetectionAction::Drop);
}

TEST(RuleEngine, AlertAloneAndNoMatchAllow) {
    auto rule = test_rule();
    rule["action"] = "alert";
    test::RuleHarness h(Json::array({rule}));
    const auto decision = h.send({.seq = 1, .data = "HELLO"});
    EXPECT_EQ(decision.action, DetectionAction::Allow);
    EXPECT_FALSE(decision.terminal_sid);
    EXPECT_EQ(decision.matches.size(), 1);
    RuleEngine empty(RuleSet{});
    EXPECT_EQ(empty.evaluate(h.packet).action, DetectionAction::Allow);
}

TEST(RuleEngine, OutOfOrderGapAndWrapPreserveFirstSeenData) {
    test::RuleHarness h(Json::array({test_rule()}));
    h.send({.seq = 0xfffffffdU, .flags = 0x02});
    EXPECT_EQ(h.send({.seq = 1, .data = "LO"}).action, DetectionAction::Allow);
    EXPECT_EQ(h.send({.seq = 0xfffffffeU, .data = "HEL"}).action, DetectionAction::Drop);
    EXPECT_EQ(h.send({.seq = 0xfffffffeU, .data = "XXXXX"}).action, DetectionAction::Drop);
}

TEST(RuleEngine, KmpOverlapReportsLargestRelatedEndOnly) {
    auto rule = test_rule();
    rule["content"] = "ABA";
    rule["action"] = "alert";
    test::RuleHarness h(Json::array({rule}));
    auto decision = h.send({.seq = 1, .data = "ABABA"});
    ASSERT_EQ(decision.matches.size(), 1);
    EXPECT_EQ(decision.matches[0].end_offset, 5);
    decision = h.send({.seq = 1, .data = "ABA"});
    EXPECT_TRUE(decision.matches.empty());
    EXPECT_EQ(decision.suppressed, 1);
    decision = h.send({.seq = 6, .data = "BA"});
    ASSERT_EQ(decision.matches.size(), 1);
    EXPECT_EQ(decision.matches[0].end_offset, 7);
}

TEST(RuleEngine, SuppressionIndependentAcrossDirectionFlowAndSid) {
    auto other = test_rule(2);
    other["action"] = "alert";
    auto first = test_rule(1);
    first["action"] = "alert";
    test::RuleHarness h(Json::array({other, first}));
    EXPECT_EQ(h.send({.seq = 1, .data = "HELLO"}).matches.size(), 2);
    EXPECT_EQ(h.send({.seq = 1, .data = "HELLO", .backward = true}).matches.size(), 2);
    EXPECT_EQ(h.send({.seq = 1, .data = "HELLO", .client_port = 12346}).matches.size(), 2);
    EXPECT_EQ(h.engine.stats().state_bytes, 48);
    h.engine.clear();
    EXPECT_EQ(h.engine.stats().state_bytes, 0);
    EXPECT_EQ(h.engine.stats().active_flows, 0);
}

TEST(RuleEngine, SkippedRuleDoesNotConsumeItsWatermark) {
    auto pass = test_rule(1);
    pass["action"] = "pass";
    pass["scope"] = "packet";
    pass["content"] = "LO";
    test::RuleHarness h(Json::array({pass, test_rule(2)}));
    h.send({.seq = 100, .data = "HEL"});
    EXPECT_EQ(h.send({.seq = 103, .data = "LO"}).terminal_sid, 1);
    const auto decision = h.send({.seq = 100, .data = "HEL"});
    EXPECT_EQ(decision.terminal_sid, 2);
    ASSERT_EQ(decision.matches.size(), 1);
    EXPECT_EQ(decision.matches[0].sid, 2);
}

TEST(RuleEngine, CacheBudgetBoundaryFailureAndExpiryReuse) {
    test::RuleHarness h(Json::array({test_rule()}), {.state_bytes = 8});
    EXPECT_EQ(h.send({.seq = 1, .data = "HELLO"}).action, DetectionAction::Drop);
    EXPECT_EQ(h.engine.stats().state_bytes, 8);
    EXPECT_THROW(h.send({.seq = 1, .data = "HELLO", .backward = true}), DetectionError);
    h.engine.forget_flow(1);
    EXPECT_EQ(h.engine.stats().state_bytes, 0);
    EXPECT_EQ(h.send({.seq = 1, .data = "HELLO", .client_port = 12346}).action,
              DetectionAction::Drop);
    test::RuleHarness expired(Json::array({test_rule()}), {.state_bytes = 8});
    expired.send({.seq = 1, .data = "HELLO"});
    EXPECT_EQ(
        expired.send({.seq = 1, .data = "HELLO", .at = std::chrono::seconds{120}}).matches.size(),
        1);
    EXPECT_EQ(expired.engine.stats().state_bytes, 8);
}

TEST(RuleEngine, NoMatchHasNoWatermarkArrayAndCapacityIsExplicit) {
    test::RuleHarness h(Json::array({test_rule()}), {.max_flows = 1, .state_bytes = 1});
    h.send({.seq = 1, .data = "NOT_A_MATCH"});
    EXPECT_EQ(h.engine.stats().state_bytes, 0);
    EXPECT_THROW(h.send({.seq = 1, .data = "HELLO", .client_port = 12346}), DetectionError);
}

TEST(RuleEngine, PacketFallbackWorksWithoutTrackedFlowAndHandlesBinaryBytes) {
    auto packet = test_rule(1);
    packet["scope"] = "packet";
    test::RuleHarness h(Json::array({packet, test_rule(2)}));
    h.send({.seq = 1, .data = std::string_view{"\0HELLO\xff", 7}});
    const auto decision = h.engine.evaluate(h.packet);
    EXPECT_EQ(decision.action, DetectionAction::Drop);
    EXPECT_FALSE(decision.stream_evaluated);
}

TEST(RuleEngine, RejectsMalformedContextBeforeStateMutation) {
    test::RuleHarness h(Json::array({test_rule()}));
    h.send({.seq = 99, .flags = 0x02});
    h.send({.seq = 100, .data = "HEL"});
    auto update = h.stream_update();
    update.flow_id = 999;
    EXPECT_THROW(h.engine.evaluate(h.packet, &h.tracked_flow(), &update), std::invalid_argument);
    update = h.stream_update();
    update.payload_range = ByteRange{0, 100};
    EXPECT_THROW(h.engine.evaluate(h.packet, &h.tracked_flow(), &update), std::invalid_argument);
    update = h.stream_update();
    update.newly_contiguous = std::as_bytes(std::span{"BAD", 3});
    EXPECT_THROW(h.engine.evaluate(h.packet, &h.tracked_flow(), &update), std::invalid_argument);
    EXPECT_EQ(h.engine.stats().state_bytes, 0);
}

TEST(RuleEngine, RejectsZeroConfiguration) {
    EXPECT_THROW((RuleEngine{RuleSet{}, {.max_flows = 0}}), std::invalid_argument);
    EXPECT_THROW((RuleEngine{RuleSet{}, {.state_bytes = 0}}), std::invalid_argument);
}

TEST(RuleEngine, RejectsImpossibleAckAndPayloadRangesBeforeMutation) {
    test::RuleHarness h(Json::array({test_rule()}));
    h.send({.seq = 99, .flags = 0x02});
    h.send({.seq = 100, .data = "HELLO"});
    EXPECT_EQ(h.send({.seq = 105, .flags = 0x10}).action, DetectionAction::Allow);
    const auto before = h.engine.stats().packets_evaluated;
    auto forged = h.stream_update();
    forged.payload_range = ByteRange{0, 5};
    EXPECT_THROW(h.engine.evaluate(h.packet, &h.tracked_flow(), &forged), std::invalid_argument);
    forged = h.stream_update();
    forged.newly_contiguous = forged.contiguous_prefix;
    EXPECT_THROW(h.engine.evaluate(h.packet, &h.tracked_flow(), &forged), std::invalid_argument);
    EXPECT_EQ(h.engine.stats().packets_evaluated, before);
    h.send({.seq = 105, .data = "!"});
    forged = h.stream_update();
    forged.payload_range = ByteRange{0, 5};
    EXPECT_THROW(h.engine.evaluate(h.packet, &h.tracked_flow(), &forged), std::invalid_argument);
    forged = h.stream_update();
    forged.newly_contiguous = forged.contiguous_prefix;
    EXPECT_THROW(h.engine.evaluate(h.packet, &h.tracked_flow(), &forged), std::invalid_argument);
}

}  // namespace
}  // namespace miniips
