#include <gtest/gtest.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <stdexcept>
#include <utility>
#include <variant>

#include "miniips/flow_table.hpp"

namespace miniips {
namespace {

using namespace std::chrono_literals;

ParsedPacket tcp_at(std::int64_t timestamp_us = 0, TcpMetadata tcp = {}) {
    ParsedPacket packet;
    packet.captured_at = std::chrono::microseconds{timestamp_us};
    packet.src_ip = 0xC0000201U;
    packet.dst_ip = 0xC6336402U;
    packet.src_port = 12345;
    packet.dst_port = 8080;
    packet.ip_total_length = 40;
    packet.ip_header_bytes = 20;
    packet.transport_header_bytes = 20;
    packet.protocol = TransportProtocol::Tcp;
    packet.tcp = tcp;
    return packet;
}

ParsedPacket reversed(ParsedPacket packet) {
    std::swap(packet.src_ip, packet.dst_ip);
    std::swap(packet.src_port, packet.dst_port);
    return packet;
}

ParsedPacket udp_at(std::int64_t timestamp_us = 0) {
    auto packet = tcp_at(timestamp_us);
    packet.protocol = TransportProtocol::Udp;
    packet.ip_total_length = 28;
    packet.transport_header_bytes = 8;
    packet.tcp.reset();
    return packet;
}

FlowObservation observed(FlowTable& table, const ParsedPacket& packet) {
    return std::get<FlowObservation>(table.observe(packet));
}

TEST(FlowKey, NormalizesBothEndpoints) {
    const auto packet = tcp_at();
    const auto key = make_flow_key(packet);
    EXPECT_EQ(key, make_flow_key(reversed(packet)));
    EXPECT_EQ(key.low.ip, 0xC0000201U);
    EXPECT_EQ(key.low.port, 12345);
    EXPECT_EQ(key.high.ip, 0xC6336402U);
    EXPECT_EQ(key.high.port, 8080);
}

TEST(FlowTable, ReverseTrafficSharesIdAndSeparatesIpBytes) {
    FlowTable table;
    const auto first = observed(table, tcp_at(1'000'000));
    auto reply = reversed(tcp_at(2'000'000));
    const std::array<std::byte, 20> payload{};
    reply.ip_total_length = 60;
    reply.payload = payload;
    const auto second = observed(table, reply);
    EXPECT_EQ(first.flow.flow_id, 1);
    EXPECT_TRUE(first.created);
    EXPECT_FALSE(second.created);
    EXPECT_EQ(second.flow.flow_id, 1);
    EXPECT_EQ(first.direction, FlowDirection::Forward);
    EXPECT_EQ(second.direction, FlowDirection::Backward);
    EXPECT_EQ(second.flow.fwd.packets, 1);
    EXPECT_EQ(second.flow.bwd.packets, 1);
    EXPECT_EQ(second.flow.fwd.bytes, 40);
    EXPECT_EQ(second.flow.bwd.bytes, 60);
    EXPECT_EQ(table.size(), 1);
}

TEST(FlowTable, SameDirectionAccumulatesOnOneId) {
    FlowTable table;
    observed(table, tcp_at(1'000'000));
    const auto result = observed(table, tcp_at(3'000'000));
    EXPECT_EQ(result.flow.flow_id, 1);
    EXPECT_EQ(result.flow.fwd.packets, 2);
    EXPECT_EQ(result.flow.fwd.bytes, 80);
    EXPECT_EQ(result.flow.bwd.packets, 0);
    EXPECT_EQ(result.flow.fwd.iat_sum_us, 2'000'000);
    EXPECT_EQ(result.flow.fwd.iat_samples, 1);
}

TEST(FlowTable, FirstObservedDirectionIsNotKeyOrder) {
    FlowTable table;
    const auto first = observed(table, reversed(tcp_at()));
    const auto second = observed(table, tcp_at(1));
    EXPECT_EQ(first.direction, FlowDirection::Forward);
    EXPECT_EQ(first.flow.first_source.ip, 0xC6336402U);
    EXPECT_EQ(second.direction, FlowDirection::Backward);
    EXPECT_EQ(second.flow.flow_id, first.flow.flow_id);
    EXPECT_EQ(second.flow.fwd.packets, 1);
    EXPECT_EQ(second.flow.bwd.packets, 1);
}

TEST(FlowTable, EveryKeyFieldSeparatesFlows) {
    FlowTable table;
    EXPECT_EQ(observed(table, tcp_at()).flow.flow_id, 1);
    auto changed = tcp_at();
    changed.src_port = 12346;
    EXPECT_EQ(observed(table, changed).flow.flow_id, 2);
    changed = tcp_at();
    changed.dst_port = 8081;
    EXPECT_EQ(observed(table, changed).flow.flow_id, 3);
    changed = tcp_at();
    changed.src_ip = 0xC0000202U;
    EXPECT_EQ(observed(table, changed).flow.flow_id, 4);
    changed = tcp_at();
    changed.dst_ip = 0xC6336403U;
    EXPECT_EQ(observed(table, changed).flow.flow_id, 5);
    EXPECT_EQ(observed(table, udp_at()).flow.flow_id, 6);
    EXPECT_EQ(table.size(), 6);
}

TEST(FlowTable, IdenticalEndpointsAreForward) {
    FlowTable table;
    auto packet = tcp_at();
    packet.dst_ip = packet.src_ip;
    packet.dst_port = packet.src_port;
    observed(table, packet);
    const auto result = observed(table, reversed(packet));
    EXPECT_EQ(result.direction, FlowDirection::Forward);
    EXPECT_EQ(result.flow.fwd.packets, 2);
    EXPECT_EQ(result.flow.bwd.packets, 0);
}

TEST(FlowTable, CaptureTimesAndBackwardIatAreSafe) {
    FlowTable table;
    observed(table, tcp_at(10));
    observed(table, tcp_at(15));
    observed(table, tcp_at(5));
    const auto forward = observed(table, tcp_at(20));
    observed(table, reversed(tcp_at(30)));
    const auto result = observed(table, reversed(tcp_at(35)));
    EXPECT_EQ(result.flow.first_seen, 5us);
    EXPECT_EQ(result.flow.last_seen, 35us);
    EXPECT_EQ(forward.flow.fwd.last_seen, 20us);
    EXPECT_EQ(result.flow.fwd.iat_sum_us, 10);
    EXPECT_EQ(result.flow.fwd.iat_samples, 3);
    EXPECT_EQ(result.flow.bwd.iat_sum_us, 5);
    EXPECT_EQ(result.flow.bwd.iat_samples, 1);
}

TEST(FlowTable, CountsTcpFlagsByDirection) {
    FlowTable table;
    observed(table, tcp_at(0, {0, 0, 0x02}));
    observed(table, reversed(tcp_at(1, {0, 0, 0x12})));
    observed(table, tcp_at(2, {0, 0, 0x10}));
    observed(table, tcp_at(3, {0, 0, 0x18}));
    observed(table, tcp_at(4, {0, 0, 0x11}));
    const auto result = observed(table, reversed(tcp_at(5, {0, 0, 0x14})));
    EXPECT_EQ(result.flow.fwd.syn_count, 1);
    EXPECT_EQ(result.flow.bwd.syn_count, 1);
    EXPECT_EQ(result.flow.fwd.ack_count, 3);
    EXPECT_EQ(result.flow.bwd.ack_count, 2);
    EXPECT_EQ(result.flow.fwd.fin_count, 1);
    EXPECT_EQ(result.flow.bwd.rst_count, 1);
    EXPECT_EQ(result.flow.fwd.psh_count, 1);
    EXPECT_EQ(result.flow.tcp_state, TcpFlowState::Reset);
}

TEST(FlowTable, HandshakeRequiresObservedOppositeSynAck) {
    FlowTable partial;
    EXPECT_EQ(observed(partial, tcp_at(0, {0, 0, 0x10})).flow.tcp_state, TcpFlowState::Observed);
    FlowTable table;
    EXPECT_EQ(observed(table, tcp_at(0, {0, 0, 0x02})).flow.tcp_state, TcpFlowState::SynSeen);
    EXPECT_EQ(observed(table, tcp_at(1, {0, 0, 0x10})).flow.tcp_state, TcpFlowState::SynSeen);
    observed(table, tcp_at(2, {0, 0, 0x12}));
    EXPECT_EQ(observed(table, tcp_at(3, {0, 0, 0x10})).flow.tcp_state, TcpFlowState::SynSeen);
    observed(table, reversed(tcp_at(4, {0, 0, 0x12})));
    EXPECT_EQ(observed(table, tcp_at(5, {0, 0, 0x10})).flow.tcp_state, TcpFlowState::Established);
}

TEST(FlowTable, FinAndResetStatesDoNotReopen) {
    FlowTable table;
    EXPECT_EQ(observed(table, tcp_at(0, {0, 0, 0x11})).flow.tcp_state, TcpFlowState::Closing);
    EXPECT_EQ(observed(table, reversed(tcp_at(1, {0, 0, 0x10}))).flow.tcp_state,
              TcpFlowState::Closing);
    EXPECT_EQ(observed(table, reversed(tcp_at(2, {0, 0, 0x11}))).flow.tcp_state,
              TcpFlowState::Closed);
    EXPECT_EQ(observed(table, tcp_at(3, {0, 0, 0x02})).flow.tcp_state, TcpFlowState::Closed);
    EXPECT_EQ(observed(table, tcp_at(4, {0, 0, 0x04})).flow.tcp_state, TcpFlowState::Reset);
    const auto result = observed(table, tcp_at(5, {0, 0, 0x10}));
    EXPECT_EQ(result.flow.tcp_state, TcpFlowState::Reset);
    EXPECT_EQ(result.flow.flow_id, 1);
    EXPECT_EQ(result.flow.fwd.packets, 4);
}

TEST(FlowTable, UdpHasNoTcpStateOrFlagCounts) {
    FlowTable table;
    observed(table, udp_at());
    const auto result = observed(table, reversed(udp_at(1)));
    EXPECT_FALSE(result.flow.tcp_state.has_value());
    EXPECT_EQ(result.flow.fwd.bytes, 28);
    EXPECT_EQ(result.flow.bwd.bytes, 28);
    EXPECT_EQ(result.flow.fwd.syn_count, 0);
    EXPECT_EQ(result.flow.bwd.ack_count, 0);
}

TEST(FlowTable, ExpiryBoundaryRemovesLookupAndReusesTupleWithNewId) {
    FlowTable table;
    const auto first = observed(table, tcp_at(1'000'000));
    EXPECT_EQ(table.expire(120'999'999us), 0);
    EXPECT_EQ(table.expire(121s), 1);
    EXPECT_FALSE(table.find(make_flow_key(tcp_at())).has_value());
    const auto second = observed(table, tcp_at(121'000'000));
    EXPECT_EQ(second.flow.flow_id, 2);
    EXPECT_TRUE(second.created);
    EXPECT_EQ(first.flow.flow_id, 1);
    EXPECT_EQ(first.flow.fwd.packets, 1);
    EXPECT_EQ(table.stats().created, 2);
    EXPECT_EQ(table.stats().expired, 1);
}

TEST(FlowTable, PacketExactlyAtIdleBoundaryStartsNewFlow) {
    FlowTable table;
    observed(table, tcp_at());
    const auto result = observed(table, tcp_at(120'000'000));
    EXPECT_EQ(result.flow.flow_id, 2);
    EXPECT_EQ(result.flow.fwd.packets, 1);
    EXPECT_EQ(table.stats().expired, 1);
    EXPECT_EQ(table.size(), 1);
}

TEST(FlowTable, ReverseActivityRenewsIdleTime) {
    FlowTable table;
    observed(table, tcp_at(1'000'000));
    EXPECT_EQ(observed(table, reversed(tcp_at(120'000'000))).flow.flow_id, 1);
    EXPECT_EQ(table.expire(239'999'999us), 0);
    EXPECT_EQ(table.expire(240s), 1);
}

TEST(FlowTable, BackwardClockCannotDelayExpiry) {
    FlowTable table(FlowTableConfig{4, 10s});
    const auto first = tcp_at(100'000'000);
    auto other = tcp_at(105'000'000);
    other.dst_port = 8081;
    observed(table, first);
    observed(table, other);
    EXPECT_EQ(table.expire(104s), 0);
    EXPECT_EQ(table.expire(110s), 1);
    const auto late = observed(table, tcp_at(90'000'000));
    EXPECT_EQ(late.flow.flow_id, 3);
    EXPECT_EQ(late.flow.first_seen, 90s);
    EXPECT_EQ(table.expire(114s), 0);
    EXPECT_EQ(table.expire(115s), 1);
    EXPECT_EQ(table.expire(120s), 1);
    EXPECT_EQ(table.size(), 0);
}

TEST(FlowTable, CapacityPreservesExistingFlowAndRejectsNewKey) {
    FlowTable table(FlowTableConfig{1, 120s});
    observed(table, tcp_at());
    const auto rejected = table.observe(udp_at(1));
    EXPECT_EQ(std::get<FlowError>(rejected), FlowError::CapacityExceeded);
    const auto reply = observed(table, reversed(tcp_at(2)));
    EXPECT_EQ(reply.flow.flow_id, 1);
    EXPECT_EQ(reply.flow.bwd.packets, 1);
    EXPECT_EQ(table.stats().created, 1);
    EXPECT_EQ(table.stats().rejected, 1);
    EXPECT_EQ(table.stats().active, 1);
}

TEST(FlowTable, ExpiryReleasesCapacity) {
    FlowTable table(FlowTableConfig{1, 1s});
    observed(table, tcp_at());
    EXPECT_EQ(std::get<FlowError>(table.observe(udp_at(500'000))), FlowError::CapacityExceeded);
    EXPECT_EQ(observed(table, udp_at(1'000'000)).flow.flow_id, 2);
    EXPECT_EQ(table.stats().expired, 1);
    EXPECT_EQ(table.stats().rejected, 1);
    EXPECT_EQ(table.size(), 1);
}

TEST(FlowTable, ManyFlowsStayWithinConfiguredBound) {
    FlowTable table(FlowTableConfig{8, 1s});
    for (std::uint16_t index = 0; index < 32; ++index) {
        auto packet = tcp_at();
        packet.src_port = static_cast<std::uint16_t>(1000U + index);
        table.observe(packet);
        EXPECT_LE(table.size(), 8);
    }
    EXPECT_EQ(table.stats().created, 8);
    EXPECT_EQ(table.stats().rejected, 24);
    EXPECT_EQ(table.expire(1s), 8);
    EXPECT_EQ(observed(table, tcp_at(1'000'000)).flow.flow_id, 9);
}

TEST(FlowTable, SnapshotValuesSurviveChangesAndExpiry) {
    FlowTable table;
    observed(table, tcp_at());
    auto snapshot = table.find(make_flow_key(reversed(tcp_at())));
    if (!snapshot.has_value()) {
        FAIL() << "Tracked flow must be found by its reverse key.";
    }
    snapshot->fwd.packets = 999;
    EXPECT_EQ(observed(table, tcp_at(1)).flow.fwd.packets, 2);
    EXPECT_EQ(table.expire(121s), 1);
    EXPECT_EQ(snapshot->flow_id, 1);
    EXPECT_EQ(snapshot->fwd.packets, 999);
}

TEST(FlowTable, RejectsInvalidConfiguration) {
    EXPECT_THROW((FlowTable{FlowTableConfig{0, 120s}}), std::invalid_argument);
    EXPECT_THROW((FlowTable{FlowTableConfig{1, 0us}}), std::invalid_argument);
    EXPECT_THROW((FlowTable{FlowTableConfig{1, -1us}}), std::invalid_argument);
}

TEST(FlowTable, InvalidMetadataDoesNotMutateTrackedFlowOrClock) {
    FlowTable table;
    observed(table, tcp_at());
    auto bad = tcp_at(-1);
    EXPECT_THROW(table.observe(bad), std::invalid_argument);
    bad = tcp_at(200'000'000);
    bad.tcp.reset();
    EXPECT_THROW(table.observe(bad), std::invalid_argument);
    bad = udp_at(200'000'000);
    bad.tcp = TcpMetadata{};
    EXPECT_THROW(table.observe(bad), std::invalid_argument);
    bad = tcp_at(200'000'000);
    // Exercise rejection of a protocol outside the supported TCP/UDP values.
    // NOLINTNEXTLINE(clang-analyzer-optin.core.EnumCastOutOfRange)
    bad.protocol = static_cast<TransportProtocol>(255);
    EXPECT_THROW(table.observe(bad), std::invalid_argument);
    bad = tcp_at(200'000'000);
    bad.ip_total_length = 0;
    EXPECT_THROW(table.observe(bad), std::invalid_argument);
    EXPECT_THROW(table.expire(-1us), std::invalid_argument);
    const auto result = observed(table, tcp_at(1));
    EXPECT_EQ(result.flow.flow_id, 1);
    EXPECT_EQ(result.flow.fwd.packets, 2);
    EXPECT_EQ(table.stats().expired, 0);
    EXPECT_EQ(table.stats().created, 1);
}

TEST(FlowTable, ExtremeTimestampsDoNotOverflow) {
    const auto maximum = std::numeric_limits<std::int64_t>::max();
    FlowTable table(FlowTableConfig{1, std::chrono::microseconds{maximum}});
    observed(table, tcp_at());
    EXPECT_EQ(table.expire(std::chrono::microseconds{maximum - 1}), 0);
    EXPECT_EQ(table.expire(std::chrono::microseconds{maximum}), 1);
    EXPECT_EQ(observed(table, tcp_at(maximum)).flow.flow_id, 2);
    const auto result = observed(table, reversed(tcp_at(maximum)));
    EXPECT_EQ(result.flow.bwd.iat_sum_us, 0);
    EXPECT_EQ(table.expire(0us), 0);
    EXPECT_EQ(table.size(), 1);
}

}  // namespace
}  // namespace miniips
