#include <gtest/gtest.h>

#include <cstddef>
#include <limits>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "fixtures/reassembly_fixtures.hpp"
#include "miniips/cli.hpp"
#include "pcap_fixture.hpp"

namespace miniips {
namespace {

int run_reassembly(const test::TempPcap& file, const std::vector<std::string_view>& options,
                   std::ostream& output, std::ostream& errors) {
    const auto path = file.path().string();
    std::vector<std::string_view> args{"--mode", "pcap", "--input", path};
    args.insert(args.end(), options.begin(), options.end());
    return run_cli(args, output, errors);
}

TEST(ReassemblyCli, OutOfOrderHelloReportsFiveNewBytesAndFinWithoutPayloadText) {
    test::TempPcap file;
    test::write_pcap(file.path(),
                     {test::record_at(test::tcp_segment({.sequence = 99, .flags = 0x02}), 1),
                      test::record_at(test::tcp_segment({.sequence = 103, .payload = "LO"}), 2),
                      test::record_at(test::tcp_segment({.sequence = 100, .payload = "HEL"}), 3),
                      test::record_at(test::tcp_segment({.sequence = 105, .flags = 0x11}), 4)});
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(run_reassembly(file, {}, output, errors), 0);
    EXPECT_TRUE(errors.str().empty());
    EXPECT_NE(output.str().find("stream_bytes=0 stream_new_bytes=0 stream_pending_bytes=2"),
              std::string::npos);
    EXPECT_NE(output.str().find("stream_bytes=5 stream_new_bytes=5 stream_pending_bytes=0"),
              std::string::npos);
    EXPECT_NE(output.str().find("stream_closed=1"), std::string::npos);
    EXPECT_NE(output.str().find("reason=gap_filled"), std::string::npos);
    EXPECT_NE(output.str().find("reassembly_summary bytes_emitted=5"), std::string::npos);
    EXPECT_NE(output.str().find("active=0 memory_bytes=0 peak_memory_bytes=73728"),
              std::string::npos);
    EXPECT_EQ(output.str().find("HELLO"), std::string::npos);
}

TEST(ReassemblyCli, PermanentGapAndMidstreamAreExplicitAtEnd) {
    test::TempPcap file;
    test::write_pcap(file.path(),
                     {test::record_at(test::tcp_segment({.sequence = 100, .payload = "A"}), 1),
                      test::record_at(test::tcp_segment({.sequence = 103, .payload = "D"}), 2)});
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(run_reassembly(file, {}, output, errors), 0);
    EXPECT_NE(output.str().find("reason=midstream"), std::string::npos);
    EXPECT_NE(output.str().find("reassembly_end flow_id=1 direction=fwd reason=capture_end"),
              std::string::npos);
    EXPECT_NE(output.str().find("issues=midstream,gap_pending,gap,capture_end"), std::string::npos);
    EXPECT_NE(output.str().find("reassembly_summary bytes_emitted=1"), std::string::npos);
}

TEST(ReassemblyCli, DuplicateAndConflictDoNotEmitBytesAgain) {
    test::TempPcap file;
    test::write_pcap(file.path(),
                     {test::record_at(test::tcp_segment({.sequence = 100, .payload = "HEL"}), 1),
                      test::record_at(test::tcp_segment({.sequence = 100, .payload = "HEL"}), 2),
                      test::record_at(test::tcp_segment({.sequence = 100, .payload = "BAD"}), 3)});
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(run_reassembly(file, {}, output, errors), 0);
    EXPECT_NE(output.str().find("reason=overlap_conflict"), std::string::npos);
    EXPECT_NE(output.str().find("reassembly_summary bytes_emitted=3 overlap_conflicts=1"),
              std::string::npos);
}

TEST(ReassemblyCli, DepthLimitAndBudgetRejectionAreVisible) {
    test::TempPcap file;
    test::write_pcap(
        file.path(),
        {test::record_at(test::tcp_segment({.sequence = 100, .payload = "HELLO"}), 1)});
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(run_reassembly(file, {"--tcp-stream-bytes", "4", "--tcp-memory-bytes", "5"}, output,
                             errors),
              0);
    EXPECT_NE(output.str().find("reason=depth_limit"), std::string::npos);
    EXPECT_NE(output.str().find("reassembly_summary bytes_emitted=4"), std::string::npos);
    output.str("");
    EXPECT_EQ(run_reassembly(file, {"--tcp-stream-bytes", "8", "--tcp-memory-bytes", "8"}, output,
                             errors),
              0);
    EXPECT_NE(output.str().find("reason=memory_limit"), std::string::npos);
    EXPECT_NE(output.str().find("rejected=1 active=0 memory_bytes=0 peak_memory_bytes=0"),
              std::string::npos);
}

TEST(ReassemblyCli, ParserErrorAdvancesExpiryAndNewFlowCanReuseBudget) {
    test::TempPcap file;
    test::write_pcap(file.path(),
                     {test::record_at(test::tcp_segment({.sequence = 100, .payload = "A"}), 0),
                      test::record_at({std::byte{1}}, 120),
                      test::record_at(test::tcp_segment({.sequence = 500, .payload = "B"}), 121)});
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(run_reassembly(file, {"--tcp-stream-bytes", "8", "--tcp-memory-bytes", "9"}, output,
                             errors),
              0);
    EXPECT_NE(errors.str().find("parse_error packet=2"), std::string::npos);
    EXPECT_NE(output.str().find("reassembly_end flow_id=1 direction=fwd reason=idle_timeout"),
              std::string::npos);
    EXPECT_NE(output.str().find("flow_id=2 direction=fwd"), std::string::npos);
    EXPECT_NE(
        output.str().find("reassembly_summary bytes_emitted=2 overlap_conflicts=0 rejected=0"),
        std::string::npos);
    EXPECT_NE(output.str().find("peak_memory_bytes=9"), std::string::npos);
}

TEST(ReassemblyCli, UdpAndUntrackedTcpAllocateNoExtraStreamBuffer) {
    test::TempPcap file;
    test::write_pcap(
        file.path(),
        {test::record_at(test::udp_packet(), 1),
         test::record_at(test::tcp_segment({.sequence = 100, .payload = "HELLO"}), 2)});
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(run_reassembly(file, {"--max-flows", "1"}, output, errors), 0);
    EXPECT_NE(output.str().find("flow_id=untracked direction=unknown"), std::string::npos);
    EXPECT_NE(output.str().find("reassembly_summary bytes_emitted=0"), std::string::npos);
    EXPECT_NE(output.str().find("active=0 memory_bytes=0 peak_memory_bytes=0"), std::string::npos);
}

TEST(ReassemblyCli, RejectsInvalidOrDuplicateTcpLimits) {
    test::TempPcap file;
    test::write_pcap(file.path(), {});
    const std::vector<std::vector<std::string_view>> cases{
        {"--tcp-stream-bytes", "0"},
        {"--tcp-stream-bytes", "-1"},
        {"--tcp-stream-bytes", "2147483648"},
        {"--tcp-stream-bytes", "1x"},
        {"--tcp-stream-bytes", "8", "--tcp-stream-bytes", "9"},
        {"--tcp-stream-bytes"},
        {"--tcp-memory-bytes", "0"},
        {"--tcp-memory-bytes", "+1"},
        {"--tcp-memory-bytes", "18446744073709551616"},
        {"--tcp-memory-bytes", "1", "--tcp-memory-bytes", "2"},
        {"--tcp-memory-bytes"}};
    for (const auto& options : cases) {
        std::ostringstream output;
        std::ostringstream errors;
        EXPECT_EQ(run_reassembly(file, options, output, errors), 2);
        EXPECT_TRUE(output.str().empty());
        EXPECT_NE(errors.str().find("Usage:"), std::string::npos);
    }
}

TEST(ReassemblyCli, LargeValidLimitsDoNotAllocateBeforePayload) {
    test::TempPcap file;
    test::write_pcap(file.path(), {});
    const auto max_memory = std::to_string(std::numeric_limits<std::size_t>::max());
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(
        run_reassembly(file, {"--tcp-stream-bytes", "2147483647", "--tcp-memory-bytes", max_memory},
                       output, errors),
        0);
    EXPECT_NE(output.str().find("memory_bytes=0 peak_memory_bytes=0"), std::string::npos);
}

class FailingReassemblyEndBuffer : public std::stringbuf {
   protected:
    std::streamsize xsputn(const char* text, std::streamsize count) override {
        if (std::string_view{text, static_cast<std::size_t>(count)}.find("reassembly_end") !=
            std::string_view::npos) {
            return 0;
        }
        return std::stringbuf::xsputn(text, count);
    }
};

TEST(ReassemblyCli, EndEventOutputFailureIsRuntimeError) {
    test::TempPcap file;
    test::write_pcap(file.path(),
                     {test::record_at(test::tcp_segment({.sequence = 100, .payload = "A"}), 1)});
    FailingReassemblyEndBuffer buffer;
    std::ostream output(&buffer);
    std::ostringstream errors;
    EXPECT_EQ(run_reassembly(file, {}, output, errors), 1);
    EXPECT_NE(errors.str().find("Output stream failed"), std::string::npos);
}

}  // namespace
}  // namespace miniips
