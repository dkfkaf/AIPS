#include <gtest/gtest.h>

#include "fixtures/rule_fixtures.hpp"

namespace miniips {
namespace {

TEST(ReassemblyRanges, PendingGapFillAndRetransmitHaveCorrectOffsets) {
    test::RuleHarness h(nlohmann::json::array());
    h.send({.seq = 99, .flags = 0x02});
    EXPECT_FALSE(h.stream_update().payload_range);
    h.send({.seq = 103, .data = "LO"});
    EXPECT_FALSE(h.stream_update().payload_range);
    h.send({.seq = 100, .data = "HEL"});
    EXPECT_EQ(h.stream_update().payload_range, (ByteRange{0, 3}));
    EXPECT_EQ(h.stream_update().newly_contiguous.size(), 5);
    h.send({.seq = 103, .data = "XX"});
    EXPECT_EQ(h.stream_update().payload_range, (ByteRange{3, 5}));
    h.send({.seq = 105, .flags = 0x10});
    EXPECT_FALSE(h.stream_update().payload_range);
}

TEST(ReassemblyRanges, ClipBeforeAnchorDepthAndFin) {
    test::RuleHarness h(nlohmann::json::array(), {}, {.stream_bytes = 4});
    h.send({.seq = 100, .data = "AB"});
    h.send({.seq = 99, .data = "XABCDZ"});
    EXPECT_EQ(h.stream_update().payload_range, (ByteRange{0, 4}));
    h.send({.seq = 104, .flags = 0x11});
    h.send({.seq = 102, .data = "CDZ"});
    EXPECT_EQ(h.stream_update().payload_range, (ByteRange{2, 4}));
}

TEST(ReassemblyRanges, RejectWholeSegmentAndDisabledDirectionsHaveNoRange) {
    test::RuleHarness h(nlohmann::json::array());
    h.send({.seq = 99, .flags = 0x02});
    h.send({.seq = 100, .data = "HELLO"});
    h.send({.seq = 100, .data = "X", .flags = 0x11});
    EXPECT_FALSE(h.stream_update().payload_range);
    h.send({.seq = 100, .data = "X", .flags = 0x06});
    EXPECT_FALSE(h.stream_update().payload_range);
    h.send({.seq = 500, .flags = 0x02});
    h.send({.seq = 105, .data = "X"});
    EXPECT_FALSE(h.stream_update().payload_range);
    h.send({.seq = 105, .flags = 0x04});
    h.send({.seq = 105, .data = "X"});
    EXPECT_FALSE(h.stream_update().payload_range);
}

TEST(ReassemblyRanges, WrapAmbiguityAndMemoryRejection) {
    test::RuleHarness h(nlohmann::json::array());
    h.send({.seq = 0xfffffffeU, .flags = 0x02});
    h.send({.seq = 0xffffffffU, .data = "AB"});
    EXPECT_EQ(h.stream_update().payload_range, (ByteRange{0, 2}));
    h.send({.seq = 0x7fffffffU, .data = "X"});
    EXPECT_FALSE(h.stream_update().payload_range);
    test::RuleHarness limited(nlohmann::json::array(), {}, {.memory_bytes = 1});
    limited.send({.seq = 1, .data = "HELLO"});
    EXPECT_FALSE(limited.stream_update().payload_range);
}

}  // namespace
}  // namespace miniips
