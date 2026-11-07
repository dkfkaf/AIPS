#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include "miniips/flow_table.hpp"
#include "miniips/tcp_reassembler.hpp"

namespace miniips {
namespace {

struct Segment {
    std::uint32_t seq{};
    std::string_view data{};
    std::uint8_t flags{0x18};
    bool backward{};
    std::uint16_t client_port{12345};
};

std::string text_of(std::span<const std::byte> bytes) {
    std::string text;
    for (const auto byte : bytes) {
        text.push_back(static_cast<char>(std::to_integer<unsigned char>(byte)));
    }
    return text;
}

class ReassemblyHarness {
   public:
    explicit ReassemblyHarness(TcpReassemblyConfig config = {}) : assembler(config) {}

    ReassemblyUpdate send(Segment segment) {
        storage.clear();
        for (const char value : segment.data) {
            storage.push_back(static_cast<std::byte>(value));
        }
        ParsedPacket packet;
        packet.src_ip = segment.backward ? 0xC6336402U : 0xC0000201U;
        packet.dst_ip = segment.backward ? 0xC0000201U : 0xC6336402U;
        packet.src_port = segment.backward ? 8080 : segment.client_port;
        packet.dst_port = segment.backward ? segment.client_port : 8080;
        packet.ip_header_bytes = 20;
        packet.transport_header_bytes = 20;
        packet.ip_total_length = static_cast<std::uint16_t>(40 + storage.size());
        packet.tcp = TcpMetadata{segment.seq, 0, segment.flags};
        packet.payload = storage;
        const auto observed = flows.observe(packet);
        return assembler.observe(std::get<FlowObservation>(observed), packet);
    }

    FlowTable flows;
    TcpReassembler assembler;
    std::vector<std::byte> storage;
};

TEST(TcpSequence, OrdersWrapAndDistinguishesHalfRange) {
    EXPECT_EQ(compare_tcp_sequence(7, 7), SequenceOrder::Equal);
    EXPECT_EQ(compare_tcp_sequence(0, 0xffffffffU), SequenceOrder::After);
    EXPECT_EQ(compare_tcp_sequence(0xffffffffU, 0), SequenceOrder::Before);
    EXPECT_EQ(compare_tcp_sequence(0x7fffffffU, 0), SequenceOrder::After);
    EXPECT_EQ(compare_tcp_sequence(0x80000000U, 0), SequenceOrder::Ambiguous);
    EXPECT_EQ(compare_tcp_sequence(0, 0x80000000U), SequenceOrder::Ambiguous);
}

TEST(TcpReassembler, JoinsHelloWithoutDuplicatingRetransmission) {
    ReassemblyHarness h;
    h.send({.seq = 99, .flags = 0x02});
    EXPECT_EQ(text_of(h.send({.seq = 100, .data = "HEL"}).newly_contiguous), "HEL");
    auto result = h.send({.seq = 103, .data = "LO"});
    EXPECT_EQ(text_of(result.contiguous_prefix), "HELLO");
    EXPECT_EQ(text_of(result.newly_contiguous), "LO");
    result = h.send({.seq = 100, .data = "HELLO"});
    EXPECT_TRUE(result.newly_contiguous.empty());
    EXPECT_EQ(text_of(result.contiguous_prefix), "HELLO");
    EXPECT_EQ(h.assembler.stats().bytes_emitted, 5);
    EXPECT_FALSE(has_issue(result.issues, ReassemblyIssue::Midstream));
}

TEST(TcpReassembler, OutOfOrderWaitsForGapAndOwnsPendingData) {
    ReassemblyHarness h;
    h.send({.seq = 99, .flags = 0x02});
    auto result = h.send({.seq = 103, .data = "LO"});
    EXPECT_TRUE(result.contiguous_prefix.empty());
    EXPECT_EQ(result.pending_bytes, 2);
    EXPECT_TRUE(has_issue(result.issues, ReassemblyIssue::GapPending));
    h.storage.assign(100, std::byte{'X'});
    result = h.send({.seq = 100, .data = "HEL"});
    EXPECT_EQ(text_of(result.newly_contiguous), "HELLO");
    EXPECT_EQ(result.pending_bytes, 0);
    EXPECT_FALSE(has_issue(result.issues, ReassemblyIssue::GapPending));
    EXPECT_TRUE(has_issue(result.events, ReassemblyIssue::GapFilled));
}

TEST(TcpReassembler, MultipleGapsOnlyExposeContiguousBytes) {
    ReassemblyHarness h;
    h.send({.seq = 99, .flags = 0x02});
    h.send({.seq = 104, .data = "E"});
    h.send({.seq = 102, .data = "C"});
    auto result = h.send({.seq = 100, .data = "AB"});
    EXPECT_EQ(text_of(result.contiguous_prefix), "ABC");
    EXPECT_EQ(result.pending_bytes, 1);
    EXPECT_EQ(text_of(h.send({.seq = 103, .data = "D"}).newly_contiguous), "DE");
}

TEST(TcpReassembler, FirstSeenWinsForPendingAndDeliveredOverlap) {
    ReassemblyHarness h;
    h.send({.seq = 99, .flags = 0x02});
    h.send({.seq = 102, .data = "LLO"});
    auto result = h.send({.seq = 100, .data = "HEXXX!"});
    EXPECT_EQ(text_of(result.contiguous_prefix), "HELLO!");
    EXPECT_TRUE(has_issue(result.events, ReassemblyIssue::OverlapConflict));
    result = h.send({.seq = 101, .data = "eLLO!"});
    EXPECT_EQ(text_of(result.contiguous_prefix), "HELLO!");
    EXPECT_TRUE(result.newly_contiguous.empty());
    EXPECT_TRUE(has_issue(result.events, ReassemblyIssue::OverlapConflict));
    EXPECT_EQ(h.assembler.stats().overlap_conflicts, 2);
}

TEST(TcpReassembler, IdenticalPartialOverlapAddsOnlyNewSuffix) {
    ReassemblyHarness h;
    h.send({.seq = 99, .flags = 0x02});
    h.send({.seq = 100, .data = "HELL"});
    const auto result = h.send({.seq = 102, .data = "LLO"});
    EXPECT_EQ(text_of(result.contiguous_prefix), "HELLO");
    EXPECT_EQ(text_of(result.newly_contiguous), "O");
    EXPECT_FALSE(has_issue(result.events, ReassemblyIssue::OverlapConflict));
}

TEST(TcpReassembler, KeepsDirectionSequenceSpacesIndependent) {
    ReassemblyHarness h;
    h.send({.seq = 99, .flags = 0x02});
    h.send({.seq = 899, .flags = 0x12, .backward = true});
    h.send({.seq = 100, .data = "HEL"});
    EXPECT_EQ(text_of(h.send({.seq = 900, .data = "REPLY", .backward = true}).contiguous_prefix),
              "REPLY");
    EXPECT_EQ(text_of(h.send({.seq = 103, .data = "LO"}).contiguous_prefix), "HELLO");
}

TEST(TcpReassembler, MidstreamNeverRetroactivelyPrependsOlderData) {
    ReassemblyHarness h;
    auto result = h.send({.seq = 103, .data = "LO"});
    EXPECT_TRUE(has_issue(result.issues, ReassemblyIssue::Midstream));
    result = h.send({.seq = 100, .data = "HELLO!"});
    EXPECT_EQ(text_of(result.contiguous_prefix), "LO!");
    EXPECT_EQ(text_of(result.newly_contiguous), "!");
    EXPECT_TRUE(has_issue(result.issues, ReassemblyIssue::BeforeAnchor));
}

TEST(TcpReassembler, PureAckDoesNotAnchorAndSynPayloadConsumesSequence) {
    ReassemblyHarness h;
    h.send({.seq = 1, .flags = 0x10});
    const auto result = h.send({.seq = 99, .data = "HELLO", .flags = 0x02});
    EXPECT_EQ(text_of(result.contiguous_prefix), "HELLO");
    EXPECT_FALSE(has_issue(result.issues, ReassemblyIssue::Midstream));
}

TEST(TcpReassembler, WrapsAcrossZeroIncludingPendingAndRetransmittedData) {
    ReassemblyHarness h;
    h.send({.seq = 0xfffffffdU, .flags = 0x02});
    h.send({.seq = 1, .data = "LO"});
    auto result = h.send({.seq = 0xfffffffeU, .data = "HEL"});
    EXPECT_EQ(text_of(result.contiguous_prefix), "HELLO");
    result = h.send({.seq = 0xffffffffU, .data = "ELL"});
    EXPECT_EQ(text_of(result.contiguous_prefix), "HELLO");
    EXPECT_TRUE(result.newly_contiguous.empty());
}

TEST(TcpReassembler, RejectsHalfRangeAmbiguityWithoutFillingGap) {
    ReassemblyHarness h;
    h.send({.seq = 0xffffffffU, .flags = 0x02});
    const auto result = h.send({.seq = 0x80000000U, .data = "X"});
    EXPECT_TRUE(result.contiguous_prefix.empty());
    EXPECT_TRUE(has_issue(result.events, ReassemblyIssue::SequenceAmbiguous));
    EXPECT_EQ(h.assembler.stats().memory_bytes, 0);
}

TEST(TcpReassembler, AmbiguousFinBoundaryCannotPoisonLaterValidFin) {
    for (const std::string_view data : {"X", "XY"}) {
        ReassemblyHarness h;
        h.send({.seq = 0xffffffffU, .flags = 0x02});
        auto result = h.send({.seq = 0x7fffffffU, .data = data, .flags = 0x11});
        EXPECT_TRUE(has_issue(result.events, ReassemblyIssue::SequenceAmbiguous));
        EXPECT_FALSE(result.fin_seen);
        EXPECT_FALSE(has_issue(result.issues, ReassemblyIssue::GapPending));
        EXPECT_EQ(h.assembler.stats().memory_bytes, 0);
        result = h.send({.seq = 0, .flags = 0x11});
        EXPECT_TRUE(result.closed);
        EXPECT_FALSE(has_issue(result.events, ReassemblyIssue::InvalidSegment));
    }
}

TEST(TcpReassembler, FinAheadWaitsForMissingBytesAndDoesNotCloseOppositeDirection) {
    ReassemblyHarness h;
    h.send({.seq = 99, .flags = 0x02});
    auto result = h.send({.seq = 105, .flags = 0x11});
    EXPECT_TRUE(result.fin_seen);
    EXPECT_FALSE(result.closed);
    EXPECT_TRUE(has_issue(result.issues, ReassemblyIssue::GapPending));
    result = h.send({.seq = 100, .data = "HELLO"});
    EXPECT_TRUE(result.closed);
    EXPECT_EQ(text_of(result.contiguous_prefix), "HELLO");
    EXPECT_FALSE(h.send({.seq = 500, .data = "R", .backward = true}).closed);
    result = h.send({.seq = 105, .data = "X"});
    EXPECT_TRUE(has_issue(result.events, ReassemblyIssue::InvalidSegment));
    EXPECT_EQ(text_of(result.contiguous_prefix), "HELLO");
}

TEST(TcpReassembler, LaterFinCannotTruncateAlreadySeenData) {
    ReassemblyHarness h;
    h.send({.seq = 99, .flags = 0x02});
    h.send({.seq = 110, .data = "X"});
    auto result = h.send({.seq = 105, .flags = 0x11});
    EXPECT_FALSE(result.fin_seen);
    EXPECT_TRUE(has_issue(result.events, ReassemblyIssue::InvalidSegment));
    result = h.send({.seq = 100, .data = "0123456789"});
    EXPECT_EQ(text_of(result.contiguous_prefix), "0123456789X");
}

TEST(TcpReassembler, FinBehindDeliveredPrefixIsRejectedBeforePayloadMutation) {
    ReassemblyHarness h;
    h.send({.seq = 99, .flags = 0x02});
    h.send({.seq = 100, .data = "HELLO"});
    const auto result = h.send({.seq = 100, .data = "x", .flags = 0x11});
    EXPECT_FALSE(result.fin_seen);
    EXPECT_TRUE(has_issue(result.events, ReassemblyIssue::InvalidSegment));
    EXPECT_FALSE(has_issue(result.events, ReassemblyIssue::OverlapConflict));
    EXPECT_EQ(text_of(result.contiguous_prefix), "HELLO");
}

TEST(TcpReassembler, BareFinAnchorsEmptyMidstreamAndDuplicateFinIsHarmless) {
    ReassemblyHarness h;
    auto result = h.send({.seq = 100, .flags = 0x11});
    EXPECT_TRUE(result.closed);
    EXPECT_TRUE(has_issue(result.issues, ReassemblyIssue::Midstream));
    result = h.send({.seq = 100, .flags = 0x11});
    EXPECT_FALSE(has_issue(result.events, ReassemblyIssue::InvalidSegment));
    EXPECT_TRUE(h.send({.seq = 99, .data = "A"}).contiguous_prefix.empty());
}

TEST(TcpReassembler, InvalidSynRstDoesNotResetOrReleaseValidBuffers) {
    ReassemblyHarness h;
    h.send({.seq = 99, .flags = 0x02});
    h.send({.seq = 100, .data = "HEL"});
    const auto memory = h.assembler.stats().memory_bytes;
    auto result = h.send({.seq = 777, .data = "X", .flags = 0x06});
    EXPECT_EQ(h.assembler.stats().memory_bytes, memory);
    EXPECT_TRUE(has_issue(result.events, ReassemblyIssue::InvalidSegment));
    EXPECT_EQ(text_of(h.send({.seq = 103, .data = "LO"}).contiguous_prefix), "HELLO");
    result = h.send({.seq = 104, .flags = 0x03});
    EXPECT_TRUE(has_issue(result.events, ReassemblyIssue::InvalidSegment));
}

TEST(TcpReassembler, ResetFreesBothDirectionsAndPreventsSilentRestart) {
    ReassemblyHarness h;
    h.send({.seq = 100, .data = "A"});
    h.send({.seq = 500, .data = "B", .backward = true});
    auto result = h.send({.seq = 101, .flags = 0x04});
    EXPECT_TRUE(has_issue(result.issues, ReassemblyIssue::Reset));
    EXPECT_EQ(h.assembler.stats().memory_bytes, 0);
    result = h.send({.seq = 501, .data = "C", .backward = true});
    EXPECT_TRUE(result.contiguous_prefix.empty());
    EXPECT_TRUE(has_issue(result.issues, ReassemblyIssue::Reset));
    EXPECT_EQ(h.assembler.stats().memory_bytes, 0);
}

TEST(TcpReassembler, ResetNeverReportsAnEmptyFinAsClosed) {
    ReassemblyHarness h;
    h.send({.seq = 100, .flags = 0x11});
    const auto result = h.send({.seq = 101, .flags = 0x04});
    EXPECT_FALSE(result.closed);
    EXPECT_TRUE(has_issue(result.issues, ReassemblyIssue::Reset));
}

TEST(TcpReassembler, ResetAfterFilledFinDoesNotManufactureGap) {
    ReassemblyHarness h;
    h.send({.seq = 99, .flags = 0x02});
    const auto closed = h.send({.seq = 100, .data = "HELLO", .flags = 0x11});
    ASSERT_TRUE(closed.closed);
    ASSERT_FALSE(has_issue(closed.issues, ReassemblyIssue::GapPending));
    const auto reset = h.send({.seq = 106, .flags = 0x04});
    EXPECT_FALSE(has_issue(reset.issues, ReassemblyIssue::GapPending));
    EXPECT_FALSE(has_issue(reset.issues, ReassemblyIssue::Gap));
    ReassemblyIssues ended;
    h.assembler.finish_all(ReassemblyEnd::CaptureEnd,
                           [&](const ReassemblyUpdate& update) { ended = update.issues; });
    EXPECT_FALSE(has_issue(ended, ReassemblyIssue::GapPending));
    EXPECT_FALSE(has_issue(ended, ReassemblyIssue::Gap));
    EXPECT_TRUE(has_issue(ended, ReassemblyIssue::Reset));
    EXPECT_EQ(h.assembler.stats().memory_bytes, 0);
}

TEST(TcpReassembler, ResetPreservesExistingGapWithoutReportingPendingBytes) {
    ReassemblyHarness h;
    h.send({.seq = 99, .flags = 0x02});
    h.send({.seq = 105, .flags = 0x11});
    const auto reset = h.send({.seq = 106, .flags = 0x04});
    EXPECT_FALSE(has_issue(reset.issues, ReassemblyIssue::GapPending));
    EXPECT_TRUE(has_issue(reset.issues, ReassemblyIssue::Gap));
    EXPECT_EQ(reset.pending_bytes, 0);
    ReassemblyIssues ended;
    h.assembler.finish_all(ReassemblyEnd::CaptureEnd,
                           [&](const ReassemblyUpdate& update) { ended = update.issues; });
    EXPECT_TRUE(has_issue(ended, ReassemblyIssue::Gap));
    EXPECT_FALSE(has_issue(ended, ReassemblyIssue::GapPending));
}

TEST(TcpReassembler, CapacityRejectedIdCannotRestartAfterSpaceIsFreed) {
    ReassemblyHarness h({.max_flows = 1});
    h.send({.seq = 99, .flags = 0x02});
    h.send({.seq = 499, .flags = 0x02, .client_port = 12346});
    h.assembler.finish_flow(1, ReassemblyEnd::IdleTimeout, {});
    const auto result = h.send({.seq = 500, .data = "late", .client_port = 12346});
    EXPECT_TRUE(has_issue(result.issues, ReassemblyIssue::CapacityLimit));
    EXPECT_TRUE(result.contiguous_prefix.empty());
    EXPECT_EQ(h.assembler.stats().active_flows, 0);
}

TEST(TcpReassembler, RepeatedSynKeepsStateButNewSynDisablesDirection) {
    ReassemblyHarness h;
    h.send({.seq = 99, .flags = 0x02});
    h.send({.seq = 100, .data = "HEL"});
    h.send({.seq = 99, .flags = 0x02});
    EXPECT_EQ(text_of(h.send({.seq = 103, .data = "LO"}).contiguous_prefix), "HELLO");
    auto result = h.send({.seq = 500, .flags = 0x02});
    EXPECT_TRUE(has_issue(result.issues, ReassemblyIssue::SessionReuse));
    EXPECT_TRUE(h.send({.seq = 105, .data = "X"}).newly_contiguous.empty());
}

TEST(TcpReassembler, DepthBoundaryAndBitmapAreIncludedInBudget) {
    ReassemblyHarness h({.stream_bytes = 9, .memory_bytes = 11});
    h.send({.seq = 99, .flags = 0x02});
    auto result = h.send({.seq = 100, .data = "123456789"});
    EXPECT_EQ(h.assembler.stats().memory_bytes, 11);
    EXPECT_EQ(result.contiguous_prefix.size(), 9);
    EXPECT_FALSE(has_issue(result.issues, ReassemblyIssue::DepthLimit));
    result = h.send({.seq = 109, .data = "X"});
    EXPECT_TRUE(has_issue(result.issues, ReassemblyIssue::DepthLimit));
    EXPECT_TRUE(result.newly_contiguous.empty());
    EXPECT_EQ(h.assembler.stats().memory_bytes, 11);
}

TEST(TcpReassembler, PartialDepthCrossingKeepsOnlyAllowedPrefix) {
    ReassemblyHarness h({.stream_bytes = 4, .memory_bytes = 5});
    h.send({.seq = 99, .flags = 0x02});
    const auto result = h.send({.seq = 100, .data = "HELLO"});
    EXPECT_EQ(text_of(result.contiguous_prefix), "HELL");
    EXPECT_TRUE(has_issue(result.issues, ReassemblyIssue::DepthLimit));
}

TEST(TcpReassembler, SharedBudgetRejectsDirectionPermanentlyUntilFlowEnds) {
    ReassemblyHarness h({.stream_bytes = 8, .memory_bytes = 9});
    h.send({.seq = 100, .data = "A"});
    auto result = h.send({.seq = 500, .data = "B", .backward = true});
    EXPECT_TRUE(has_issue(result.issues, ReassemblyIssue::MemoryLimit));
    EXPECT_TRUE(result.contiguous_prefix.empty());
    result = h.send({.seq = 10, .data = "C", .client_port = 12346});
    EXPECT_TRUE(has_issue(result.issues, ReassemblyIssue::MemoryLimit));
    h.assembler.finish_flow(1, ReassemblyEnd::IdleTimeout, {});
    EXPECT_EQ(h.assembler.stats().memory_bytes, 0);
    result = h.send({.seq = 11, .data = "D", .client_port = 12346});
    EXPECT_TRUE(result.contiguous_prefix.empty());
    EXPECT_TRUE(has_issue(result.issues, ReassemblyIssue::MemoryLimit));
    result = h.send({.seq = 1, .data = "E", .client_port = 12347});
    EXPECT_EQ(text_of(result.contiguous_prefix), "E");
    EXPECT_EQ(h.assembler.stats().peak_memory_bytes, 9);
}

TEST(TcpReassembler, FinalizationRecordsGapAndFreesMemory) {
    ReassemblyHarness h;
    h.send({.seq = 99, .flags = 0x02});
    h.send({.seq = 103, .data = "LO"});
    ReassemblyIssues final_issues;
    h.assembler.finish_all(ReassemblyEnd::CaptureEnd, [&](const ReassemblyUpdate& update) {
        final_issues = update.issues;
        EXPECT_TRUE(update.contiguous_prefix.empty());
        EXPECT_EQ(update.pending_bytes, 2);
    });
    EXPECT_TRUE(has_issue(final_issues, ReassemblyIssue::Gap));
    EXPECT_TRUE(has_issue(final_issues, ReassemblyIssue::CaptureEnd));
    EXPECT_EQ(h.assembler.stats().memory_bytes, 0);
    EXPECT_EQ(h.assembler.stats().active_flows, 0);
}

TEST(TcpReassembler, FinalizationFreesStateEvenWhenSinkThrows) {
    ReassemblyHarness h;
    h.send({.seq = 100, .data = "A"});
    EXPECT_THROW(h.assembler.finish_all(
                     ReassemblyEnd::CaptureEnd,
                     [](const ReassemblyUpdate&) { throw std::runtime_error("sink failed"); }),
                 std::runtime_error);
    EXPECT_EQ(h.assembler.stats().memory_bytes, 0);
    EXPECT_EQ(h.assembler.stats().active_flows, 0);
}

TEST(TcpReassembler, LimitsFixedMetadataWithoutAllocatingPayloadOnSyn) {
    ReassemblyHarness h({.max_flows = 1});
    h.send({.seq = 99, .flags = 0x02});
    const auto result = h.send({.seq = 99, .flags = 0x02, .client_port = 12346});
    EXPECT_TRUE(has_issue(result.issues, ReassemblyIssue::CapacityLimit));
    EXPECT_EQ(h.assembler.stats().active_flows, 1);
    EXPECT_EQ(h.assembler.stats().memory_bytes, 0);
}

TEST(TcpReassembler, RejectsInvalidConfiguration) {
    EXPECT_THROW((TcpReassembler{TcpReassemblyConfig{.stream_bytes = 0}}), std::invalid_argument);
    EXPECT_THROW((TcpReassembler{TcpReassemblyConfig{.stream_bytes = 0x80000000ULL}}),
                 std::invalid_argument);
    EXPECT_THROW((TcpReassembler{TcpReassemblyConfig{.memory_bytes = 0}}), std::invalid_argument);
    EXPECT_THROW((TcpReassembler{TcpReassemblyConfig{.max_flows = 0}}), std::invalid_argument);
}

TEST(TcpReassembler, RejectsInvalidObservationBeforeMutation) {
    TcpReassembler assembler;
    FlowObservation flow;
    ParsedPacket packet;
    EXPECT_THROW(assembler.observe(flow, packet), std::invalid_argument);
    packet.tcp = TcpMetadata{};
    packet.ip_total_length = 40;
    packet.ip_header_bytes = packet.transport_header_bytes = 20;
    flow.flow.flow_id = 1;
    flow.flow.key = make_flow_key(packet);
    flow.flow.first_source = {packet.src_ip, packet.src_port};
    packet.payload = std::as_bytes(std::span{"bad", 3});
    EXPECT_THROW(assembler.observe(flow, packet), std::invalid_argument);
    EXPECT_EQ(assembler.stats().active_flows, 0);
}

}  // namespace
}  // namespace miniips
