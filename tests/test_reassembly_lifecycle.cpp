#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <variant>
#include <vector>

#include "miniips/flow_table.hpp"
#include "miniips/tcp_reassembler.hpp"

namespace miniips {
namespace {

ParsedPacket tcp_at(std::chrono::microseconds at, TcpMetadata tcp) {
    static constexpr std::array PAYLOAD{std::byte{'A'}};
    ParsedPacket packet;
    packet.captured_at = at;
    packet.src_ip = 0xC0000201;
    packet.dst_ip = 0xC6336402;
    packet.src_port = 12345;
    packet.dst_port = 8080;
    packet.ip_header_bytes = packet.transport_header_bytes = 20;
    packet.ip_total_length = 41;
    packet.tcp = tcp;
    packet.payload = PAYLOAD;
    return packet;
}

TEST(ReassemblyLifecycle, AutomaticExpiryReleasesBytesBeforeNewIdUsesBudget) {
    FlowTable flows({.max_entries = 1, .idle_timeout = std::chrono::microseconds{10}});
    TcpReassembler assembler({.stream_bytes = 8, .memory_bytes = 9, .max_flows = 1});
    auto packet = tcp_at(std::chrono::microseconds{0}, {100, 0, 0x18});
    assembler.observe(std::get<FlowObservation>(flows.observe(packet)), packet);
    std::vector<std::uint64_t> expired;
    ReassemblyIssues ended;
    const FlowExpirySink cleanup = [&](const FlowSnapshot& flow) {
        expired.push_back(flow.flow_id);
        assembler.finish_flow(flow.flow_id, ReassemblyEnd::IdleTimeout,
                              [&](const ReassemblyUpdate& update) { ended = update.issues; });
    };
    packet.captured_at = std::chrono::microseconds{10};
    packet.tcp = TcpMetadata{500, 0, 0x18};
    const auto observation = std::get<FlowObservation>(flows.observe(packet, cleanup));
    ASSERT_EQ(expired, std::vector<std::uint64_t>{1});
    EXPECT_EQ(assembler.stats().memory_bytes, 0);
    EXPECT_TRUE(has_issue(ended, ReassemblyIssue::IdleTimeout));
    EXPECT_EQ(observation.flow.flow_id, 2);
    const auto result = assembler.observe(observation, packet);
    EXPECT_EQ(result.contiguous_prefix.size(), 1);
    EXPECT_EQ(assembler.stats().memory_bytes, 9);
}

TEST(ReassemblyLifecycle, BackwardClockDoesNotDelayExplicitExpiry) {
    FlowTable flows({.idle_timeout = std::chrono::microseconds{10}});
    TcpReassembler assembler;
    auto packet = tcp_at(std::chrono::microseconds{100}, {100, 0, 0x18});
    assembler.observe(std::get<FlowObservation>(flows.observe(packet)), packet);
    const FlowExpirySink cleanup = [&](const FlowSnapshot& flow) {
        assembler.finish_flow(flow.flow_id, ReassemblyEnd::IdleTimeout, {});
    };
    EXPECT_EQ(flows.expire(std::chrono::microseconds{99}, cleanup), 0);
    EXPECT_GT(assembler.stats().memory_bytes, 0);
    EXPECT_EQ(flows.expire(std::chrono::microseconds{110}, cleanup), 1);
    EXPECT_EQ(assembler.stats().memory_bytes, 0);
    EXPECT_EQ(assembler.stats().active_flows, 0);
}

TEST(ReassemblyLifecycle, InvalidPacketCannotTriggerExpiryNotification) {
    FlowTable flows({.idle_timeout = std::chrono::microseconds{10}});
    auto packet = tcp_at(std::chrono::microseconds{0}, {100, 0, 0x18});
    flows.observe(packet);
    packet.captured_at = std::chrono::microseconds{10};
    packet.tcp.reset();
    bool called = false;
    EXPECT_THROW(flows.observe(packet, [&](const FlowSnapshot&) { called = true; }),
                 std::invalid_argument);
    EXPECT_FALSE(called);
    EXPECT_EQ(flows.size(), 1);
}

TEST(ReassemblyLifecycle, ExpiryPrecedesCapacityRejectionAndAdmitsNewTuple) {
    FlowTable flows({.max_entries = 1, .idle_timeout = std::chrono::microseconds{10}});
    auto packet = tcp_at(std::chrono::microseconds{0}, {100, 0, 0x18});
    flows.observe(packet);
    packet.captured_at = std::chrono::microseconds{10};
    packet.src_port = 12346;
    bool called = false;
    const auto result = flows.observe(packet, [&](const FlowSnapshot& old) {
        EXPECT_EQ(old.flow_id, 1);
        called = true;
    });
    EXPECT_TRUE(called);
    EXPECT_EQ(std::get<FlowObservation>(result).flow.flow_id, 2);
    EXPECT_EQ(flows.stats().rejected, 0);
}

TEST(ReassemblyLifecycle, ThrowingExpiryCallbackKeepsUnprocessedFlowAndAccurateCounters) {
    FlowTable flows({.idle_timeout = std::chrono::microseconds{10}});
    auto packet = tcp_at(std::chrono::microseconds{0}, {100, 0, 0x18});
    flows.observe(packet);
    packet.src_port = 12346;
    flows.observe(packet);
    std::size_t calls = 0;
    EXPECT_THROW(flows.expire(std::chrono::microseconds{10},
                              [&](const FlowSnapshot&) {
                                  if (++calls == 2) {
                                      throw std::runtime_error("sink failed");
                                  }
                              }),
                 std::runtime_error);
    EXPECT_EQ(calls, 2);
    EXPECT_EQ(flows.size(), 1);
    EXPECT_EQ(flows.stats().expired, 1);
    EXPECT_EQ(flows.expire(std::chrono::microseconds{10}), 1);
    EXPECT_EQ(flows.stats().expired, 2);
}

}  // namespace
}  // namespace miniips
