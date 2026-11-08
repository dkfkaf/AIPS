#include <gtest/gtest.h>

#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "miniips/cli.hpp"

namespace miniips {
namespace {
TEST(LiveCli, MissingInterfaceIsCaptureErrorAfterLoggerIsReady) {
    std::ostringstream output, errors;
    const std::vector<std::string_view> args{"--mode",       "live",  "--interface",
                                             "no_such_ids0", "--log", "-"};
    EXPECT_EQ(run_cli(args, output, errors), 1);
    std::istringstream lines(output.str());
    std::string first, last;
    ASSERT_TRUE(std::getline(lines, first));
    ASSERT_TRUE(std::getline(lines, last));
    const auto error = nlohmann::json::parse(first);
    const auto stats = nlohmann::json::parse(last);
    EXPECT_EQ(error["mode"], "live");
    EXPECT_EQ(error["event_type"], "engine_error");
    EXPECT_FALSE(stats["run_complete"]);
    EXPECT_FALSE(stats["capture_complete"]);
    EXPECT_EQ(stats["capture_stats"]["status"], "not_open");
}
TEST(LiveCli, RejectsMissingConflictingAndDuplicateInputsAndLimits) {
    const std::vector<std::vector<std::string_view>> cases{
        {"--mode", "live", "--input", "a.pcap"},
        {"--mode", "live", "--interface", "lo", "--input", "a.pcap"},
        {"--mode", "pcap", "--input", "a.pcap", "--interface", "lo"},
        {"--mode", "pcap", "--input", "a.pcap", "--packet-count", "1"},
        {"--mode", "live", "--interface", "lo", "--packet-count", "0"},
        {"--mode", "live", "--interface", "lo", "--packet-count", "-1"},
        {"--mode", "live", "--interface", "lo", "--packet-count", "18446744073709551616"},
        {"--mode", "live", "--interface", "lo", "--interface", "lo"},
        {"--mode", "live", "--interface", "lo", "--packet-count", "1", "--packet-count", "2"}};
    for (const auto& args : cases) {
        std::ostringstream output, errors;
        EXPECT_EQ(run_cli(args, output, errors), 2);
        EXPECT_TRUE(output.str().empty());
    }
}
TEST(LiveCli, MaximumCountIsAcceptedBeforeMissingDeviceFailure) {
    std::ostringstream output, errors;
    const std::vector<std::string_view> args{
        "--mode", "live", "--interface", "no_such_ids0", "--packet-count", "18446744073709551615"};
    EXPECT_EQ(run_cli(args, output, errors), 1);
    EXPECT_NE(errors.str().find("capture_error:"), std::string::npos);
}
TEST(LiveCli, InvalidRulesFailBeforeOpeningLiveCapture) {
    std::ostringstream output, errors;
    const std::vector<std::string_view> args{"--mode",      "live",
                                             "--interface", "no_such_ids0",
                                             "--rules",     "/definitely/missing/ids-rules.json",
                                             "--log",       "-"};
    EXPECT_EQ(run_cli(args, output, errors), 1);
    EXPECT_NE(errors.str().find("rule_error:"), std::string::npos);
    EXPECT_TRUE(output.str().empty());
}
}  // namespace
}  // namespace miniips
