#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <limits>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "fixtures/flow_fixtures.hpp"
#include "miniips/cli.hpp"
#include "pcap_fixture.hpp"

namespace miniips {
namespace {

int run_capture(const test::TempPcap& file, const std::vector<std::string_view>& settings,
                std::ostringstream& output, std::ostringstream& errors) {
    const auto path = file.path().string();
    std::vector<std::string_view> args{"--mode", "pcap", "--input", path};
    args.insert(args.end(), settings.begin(), settings.end());
    return run_cli(args, output, errors);
}

TEST(FlowCli, RequestReplyShareIdAndDirectionalIpCounters) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record_at(test::tcp_packet(), 1),
                                   test::record_at(test::reverse_tcp_packet(), 2),
                                   test::record_at(test::tcp_packet(), 3)});
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(run_capture(file, {}, output, errors), 0);
    EXPECT_TRUE(errors.str().empty());
    EXPECT_NE(output.str().find("flow_id=1 direction=fwd fwd_packets=1 bwd_packets=0"),
              std::string::npos);
    EXPECT_NE(output.str().find("flow_id=1 direction=bwd fwd_packets=1 bwd_packets=1"),
              std::string::npos);
    EXPECT_NE(output.str().find("fwd_packets=2 bwd_packets=1 fwd_bytes=90 bwd_bytes=45"),
              std::string::npos);
    EXPECT_NE(output.str().find("flow_summary created=1 active=1 expired=0 rejected=0"),
              std::string::npos);
    EXPECT_EQ(output.str().find("HELLO"), std::string::npos);
}

TEST(FlowCli, SameTupleAfterExpiryGetsNewId) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record_at(test::tcp_packet(), 1),
                                   test::record_at(test::reverse_tcp_packet(), 2),
                                   test::record_at(test::tcp_packet(), 122)});
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(run_capture(file, {}, output, errors), 0);
    EXPECT_NE(output.str().find("flow_id=2 direction=fwd fwd_packets=1 bwd_packets=0"),
              std::string::npos);
    EXPECT_NE(output.str().find("flow_summary created=2 active=1 expired=1 rejected=0"),
              std::string::npos);
}

TEST(FlowCli, CapacityIsVisibleAndExistingFlowContinues) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record_at(test::tcp_packet(), 1),
                                   test::record_at(test::udp_packet(), 2),
                                   test::record_at(test::reverse_tcp_packet(), 3)});
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(run_capture(file, {"--max-flows", "1"}, output, errors), 0);
    EXPECT_NE(output.str().find("flow_id=untracked direction=unknown"), std::string::npos);
    EXPECT_NE(output.str().find("flow_id=1 direction=bwd fwd_packets=1 bwd_packets=1"),
              std::string::npos);
    EXPECT_NE(output.str().find("pcap_summary packets=3 parsed=3 skipped=0"), std::string::npos);
    EXPECT_NE(output.str().find("flow_summary created=1 active=1 expired=0 rejected=1"),
              std::string::npos);
    EXPECT_NE(errors.str().find("flow_error packet=2 reason=capacity_exceeded"), std::string::npos);
}

TEST(FlowCli, CustomTimeoutControlsExpiry) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record_at(test::tcp_packet(), 0),
                                   test::record_at(test::tcp_packet(), 2)});
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(run_capture(file, {"--flow-idle-timeout-seconds", "2"}, output, errors), 0);
    EXPECT_NE(output.str().find("flow_summary created=2 active=1 expired=1 rejected=0"),
              std::string::npos);
}

TEST(FlowCli, OptionsMayAppearInAnyOrder) {
    test::TempPcap file;
    test::write_pcap(file.path(), {});
    const auto path = file.path().string();
    const std::vector<std::string_view> args{
        "--max-flows", "1", "--input", path, "--flow-idle-timeout-seconds", "2", "--mode", "pcap"};
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(run_cli(args, output, errors), 0);
    EXPECT_TRUE(errors.str().empty());
    EXPECT_NE(output.str().find("flow_summary created=0 active=0 expired=0 rejected=0"),
              std::string::npos);
}

TEST(FlowCli, RejectsInvalidSettings) {
    test::TempPcap file;
    test::write_pcap(file.path(), {});
    const std::vector<std::vector<std::string_view>> cases{
        {"--max-flows", "0"},
        {"--max-flows", "-1"},
        {"--max-flows", "+1"},
        {"--max-flows", " 1"},
        {"--max-flows", "1x"},
        {"--max-flows", "18446744073709551616"},
        {"--max-flows"},
        {"--max-flows", "1", "--max-flows", "2"},
        {"--flow-idle-timeout-seconds", "0"},
        {"--flow-idle-timeout-seconds", "-1"},
        {"--flow-idle-timeout-seconds", "1.5"},
        {"--flow-idle-timeout-seconds", "9223372036855"},
        {"--flow-idle-timeout-seconds", "1", "--flow-idle-timeout-seconds", "2"},
        {"--flow-idle-timeout-seconds"},
        {"--unknown-flow-option", "1"},
    };
    for (const auto& settings : cases) {
        std::ostringstream output;
        std::ostringstream errors;
        EXPECT_EQ(run_capture(file, settings, output, errors), 2);
        EXPECT_TRUE(output.str().empty());
        EXPECT_NE(errors.str().find("Usage:"), std::string::npos);
    }
}

TEST(FlowCli, HugeValidLimitsDoNotPreallocateFlowStorage) {
    test::TempPcap file;
    test::write_pcap(file.path(), {});
    const auto entries = std::to_string(std::numeric_limits<std::size_t>::max());
    const auto seconds = std::to_string(std::numeric_limits<std::int64_t>::max() / 1'000'000);
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(run_capture(file, {"--max-flows", entries, "--flow-idle-timeout-seconds", seconds},
                          output, errors),
              0);
    EXPECT_TRUE(errors.str().empty());
    EXPECT_NE(output.str().find("flow_summary created=0 active=0 expired=0 rejected=0"),
              std::string::npos);
}

TEST(FlowCli, MalformedPacketDoesNotAllocateFlow) {
    test::TempPcap file;
    test::write_pcap(file.path(),
                     {test::record_at({std::byte{1}}, 0), test::record_at(test::tcp_packet(), 1),
                      test::record_at(test::reverse_tcp_packet(), 2)});
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(run_capture(file, {}, output, errors), 0);
    EXPECT_NE(output.str().find("packets=3 parsed=2 skipped=1"), std::string::npos);
    EXPECT_NE(output.str().find("flow_summary created=1 active=1 expired=0 rejected=0"),
              std::string::npos);
    EXPECT_NE(errors.str().find("reason=truncated_ethernet"), std::string::npos);
}

TEST(FlowCli, MalformedPacketAdvancesExpiryWithoutCreatingFlow) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record_at(test::tcp_packet(), 0),
                                   test::record_at({std::byte{1}}, 120)});
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(run_capture(file, {}, output, errors), 0);
    EXPECT_NE(output.str().find("packets=2 parsed=1 skipped=1"), std::string::npos);
    EXPECT_NE(output.str().find("flow_summary created=1 active=0 expired=1 rejected=0"),
              std::string::npos);
}

}  // namespace
}  // namespace miniips
