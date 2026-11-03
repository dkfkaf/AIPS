#include "miniips/cli.hpp"

#include <gtest/gtest.h>

#include <array>
#include <cstddef>
#include <filesystem>
#include <sstream>
#include <string>
#include <string_view>

#include "fixtures/packet_fixtures.hpp"
#include "pcap_fixture.hpp"

namespace miniips {
namespace {

TEST(PcapCli, PrintsMetadataAndCountsWithoutPayload) {
    test::TempPcap file;
    test::write_pcap(file.path(),
                     {test::record(test::tcp_packet()), test::record(test::udp_packet())});
    const auto path = file.path().string();
    const std::array<std::string_view, 4> arguments{"--mode", "pcap", "--input", path};
    std::ostringstream output;
    std::ostringstream errors;

    EXPECT_EQ(run_cli(arguments, output, errors), 0);
    EXPECT_TRUE(errors.str().empty());
    EXPECT_NE(output.str().find("timestamp_us=1250000 protocol=tcp"), std::string::npos);
    EXPECT_NE(output.str().find("src_ip=192.0.2.1 src_port=12345"), std::string::npos);
    EXPECT_NE(output.str().find("dst_ip=198.51.100.2 dst_port=8080"), std::string::npos);
    EXPECT_NE(output.str().find("protocol=udp"), std::string::npos);
    EXPECT_NE(output.str().find("packets=2 parsed=2 skipped=0"), std::string::npos);
    EXPECT_EQ(output.str().find("HELLO"), std::string::npos);
}

TEST(PcapCli, AcceptsInputOptionBeforeMode) {
    test::TempPcap file;
    test::write_pcap(file.path(), {});
    const auto path = file.path().string();
    const std::array<std::string_view, 4> arguments{"--input", path, "--mode", "pcap"};
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(run_cli(arguments, output, errors), 0);
    EXPECT_NE(output.str().find("packets=0 parsed=0 skipped=0"), std::string::npos);
}

TEST(PcapCli, ContinuesAfterMalformedPacket) {
    test::TempPcap file;
    test::write_pcap(file.path(),
                     {test::record({std::byte{1}, std::byte{2}}),
                      test::record(test::udp_packet())});
    const auto path = file.path().string();
    const std::array<std::string_view, 4> arguments{"--mode", "pcap", "--input", path};
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(run_cli(arguments, output, errors), 0);
    EXPECT_NE(output.str().find("packets=2 parsed=1 skipped=1"), std::string::npos);
    EXPECT_NE(errors.str().find("reason=truncated_ethernet"), std::string::npos);
}

TEST(PcapCli, ReportsMissingCaptureAsRuntimeError) {
    test::TempPcap file;
    const auto path = file.path().string();
    const std::array<std::string_view, 4> arguments{"--mode", "pcap", "--input", path};
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(run_cli(arguments, output, errors), 1);
    EXPECT_TRUE(output.str().empty());
    EXPECT_NE(errors.str().find("capture_error:"), std::string::npos);
}

TEST(PcapCli, DoesNotReportSuccessfulSummaryForTruncatedCapture) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record(test::tcp_packet())});
    std::filesystem::resize_file(file.path(), std::filesystem::file_size(file.path()) - 1);
    const auto path = file.path().string();
    const std::array<std::string_view, 4> arguments{"--mode", "pcap", "--input", path};
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(run_cli(arguments, output, errors), 1);
    EXPECT_EQ(output.str().find("pcap_summary"), std::string::npos);
    EXPECT_NE(errors.str().find("capture_error:"), std::string::npos);
}

TEST(PcapCli, RejectsUnsupportedOrDuplicateOptions) {
    const std::array<std::array<std::string_view, 4>, 6> cases{{
        {"--mode", "live", "--input", "unused.pcap"},
        {"--mode", "inline", "--input", "unused.pcap"},
        {"--mode", "pcap", "--input", ""},
        {"--mode", "pcap", "--mode", "pcap"},
        {"--input", "a.pcap", "--input", "b.pcap"},
        {"--rules", "rules.json", "--input", "unused.pcap"},
    }};
    for (const auto& arguments : cases) {
        std::ostringstream output;
        std::ostringstream errors;
        EXPECT_EQ(run_cli(arguments, output, errors), 2);
        EXPECT_TRUE(output.str().empty());
        EXPECT_NE(errors.str().find("Usage:"), std::string::npos);
    }
}

TEST(PcapCli, ReportsOutputFailure) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record(test::tcp_packet())});
    const auto path = file.path().string();
    const std::array<std::string_view, 4> arguments{"--mode", "pcap", "--input", path};
    std::ostringstream output;
    output.setstate(std::ios::badbit);
    std::ostringstream errors;
    EXPECT_EQ(run_cli(arguments, output, errors), 1);
    EXPECT_NE(errors.str().find("Output stream failed"), std::string::npos);
}

class FailingSyncBuffer : public std::stringbuf {
   public:
    int sync() override { return -1; }
};

TEST(PcapCli, ReportsFlushFailureAfterBufferedOutput) {
    test::TempPcap file;
    test::write_pcap(file.path(), {});
    const auto path = file.path().string();
    const std::array<std::string_view, 4> arguments{"--mode", "pcap", "--input", path};
    FailingSyncBuffer buffer;
    std::ostream output(&buffer);
    std::ostringstream errors;
    EXPECT_EQ(run_cli(arguments, output, errors), 1);
    EXPECT_NE(errors.str().find("Output stream failed"), std::string::npos);
}

}  // namespace
}  // namespace miniips
