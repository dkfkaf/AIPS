#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <vector>

#include "fixtures/packet_fixtures.hpp"
#include "miniips/packet_parser.hpp"
#include "miniips/verdict.hpp"

namespace miniips {
namespace {
struct SenderState {
    unsigned int calls{};
    std::uint32_t id{};
    QueueAction action{QueueAction::Accept};
    bool success{true};
};
bool send_record(void* context, std::uint32_t id, QueueAction action) noexcept {
    auto& state = *static_cast<SenderState*>(context);
    ++state.calls;
    state.id = id;
    state.action = action;
    return state.success;
}
TEST(InlineCore, ParsesL3WithoutEthernetAndRetainsPayloadView) {
    const auto frame = test::tcp_packet();
    const auto ip = std::span{frame}.subspan(14);
    const auto result =
        parse_packet({ip, static_cast<std::uint32_t>(ip.size()), {}, PacketLayer::Ipv4});
    const auto* packet = std::get_if<ParsedPacket>(&result);
    ASSERT_NE(packet, nullptr);
    EXPECT_EQ(packet->src_ip, 0xC0000201U);
    EXPECT_EQ(packet->payload.size(), 5);
    EXPECT_EQ(packet->payload.data(), ip.data() + 40);
}
TEST(InlineCore, L3MalformedAndUnsupportedInputsStayParseErrors) {
    auto frame = test::udp_packet();
    auto ip = std::span{frame}.subspan(14);
    EXPECT_EQ(std::get<ParseError>(parse_packet({ip.first(10), 10, {}, PacketLayer::Ipv4})),
              ParseError::TruncatedIpv4Header);
    EXPECT_EQ(std::get<ParseError>(parse_packet({ip.first(ip.size() - 1),
                                                 static_cast<std::uint32_t>(ip.size() - 1),
                                                 {},
                                                 PacketLayer::Ipv4})),
              ParseError::TruncatedIpv4Packet);
    frame[23] = std::byte{1};
    EXPECT_EQ(std::get<ParseError>(
                  parse_packet({ip, static_cast<std::uint32_t>(ip.size()), {}, PacketLayer::Ipv4})),
              ParseError::UnsupportedProtocol);
}
TEST(InlineCore, GuardSubmitsOneDecisionAndNeverRetriesRepeatedCalls) {
    SenderState sender;
    QueueStats stats;
    {
        VerdictGuard guard(7, 1, {}, {&sender, send_record}, stats);
        EXPECT_TRUE(guard.submit(QueueAction::Accept, VerdictReason::Decision));
        EXPECT_TRUE(guard.submit(QueueAction::Drop, VerdictReason::ProcessingError));
        EXPECT_EQ(guard.receipt().action, QueueAction::Accept);
    }
    EXPECT_EQ(sender.calls, 1);
    EXPECT_EQ(sender.id, 7);
    EXPECT_EQ(stats.attempts, 1);
    EXPECT_EQ(stats.accepted, 1);
    EXPECT_EQ(stats.dropped, 0);
}
TEST(InlineCore, UnwindingBeforeSubmitFallsBackToOneDrop) {
    SenderState sender;
    QueueStats stats;
    try {
        VerdictGuard guard(0, 1, {}, {&sender, send_record}, stats);
        throw std::runtime_error("inspect failed");
    } catch (const std::runtime_error&) {
        EXPECT_EQ(sender.calls, 1);
    }
    EXPECT_EQ(sender.calls, 1);
    EXPECT_EQ(sender.action, QueueAction::Drop);
    EXPECT_EQ(stats.fallback_drops, 1);
    EXPECT_EQ(stats.valid_ids, 1);
}
TEST(InlineCore, FailedSendIsAttemptedOnceAndNotCountedAsEnforced) {
    SenderState sender;
    sender.success = false;
    QueueStats stats;
    {
        VerdictGuard guard(9, 1, {}, {&sender, send_record}, stats);
        EXPECT_FALSE(guard.submit(QueueAction::Drop, VerdictReason::Decision));
        EXPECT_FALSE(guard.submit(QueueAction::Drop, VerdictReason::Shutdown));
        EXPECT_TRUE(guard.receipt().attempted);
        EXPECT_FALSE(guard.receipt().sent);
    }
    EXPECT_EQ(sender.calls, 1);
    EXPECT_EQ(stats.failed, 1);
    EXPECT_EQ(stats.dropped, 0);
}
TEST(InlineCore, FatalProcessingDropsWhileParseFailureAndLimitsKeepExistingPolicy) {
    PacketResult result;
    EXPECT_EQ(choose_inline_action(result), QueueAction::Accept);
    result.parse_error = ParseError::UnsupportedProtocol;
    EXPECT_EQ(choose_inline_action(result), QueueAction::Accept);
    result.parse_error.reset();
    result.flow = FlowError::CapacityExceeded;
    StreamSummary stream;
    stream.issues.set(static_cast<std::size_t>(ReassemblyIssue::DepthLimit));
    result.reassembly = stream;
    EXPECT_EQ(choose_inline_action(result), QueueAction::Accept);
    DetectionDecision drop;
    drop.action = DetectionAction::Drop;
    result.decision = drop;
    EXPECT_EQ(choose_inline_action(result), QueueAction::Drop);
    result.decision.reset();
    result.processing_error = ProcessingError{"detection", "state_limit", "exhausted"};
    EXPECT_EQ(choose_inline_action(result), QueueAction::Drop);
}
}  // namespace
}  // namespace miniips
