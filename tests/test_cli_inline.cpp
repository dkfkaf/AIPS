#include <gtest/gtest.h>

#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "miniips/cli.hpp"

namespace miniips {
namespace {
TEST(InlineCli, ExplicitFlagAndQueueAreRequiredBeforeAnySourceIsOpened) {
    const std::vector<std::vector<std::string_view>> cases{
        {"--mode", "inline", "--queue-num", "0"},
        {"--mode", "inline", "--enable-inline"},
        {"--mode", "inline", "--queue-num", "65536", "--enable-inline"},
        {"--mode", "inline", "--queue-num", "-1", "--enable-inline"},
        {"--mode", "inline", "--queue-num", "0", "--enable-inline", "--enable-inline"},
        {"--mode", "inline", "--queue-num", "0", "--queue-num", "1", "--enable-inline"},
        {"--mode", "inline", "--queue-num", "0", "--enable-inline", "--input", "a.pcap"},
        {"--mode", "inline", "--queue-num", "0", "--enable-inline", "--interface", "lo"},
        {"--mode", "pcap", "--input", "a.pcap", "--enable-inline"},
        {"--mode", "live", "--interface", "lo", "--queue-num", "0"}};
    for (const auto& args : cases) {
        std::ostringstream output, errors;
        EXPECT_EQ(run_cli(args, output, errors), 2);
        EXPECT_TRUE(output.str().empty());
    }
}
TEST(InlineCli, QueueBoundariesAndValuelessFlagReachRuleValidationWithoutBinding) {
    for (const auto number : {"0", "65535"}) {
        std::ostringstream output, errors;
        const std::vector<std::string_view> args{"--mode",
                                                 "inline",
                                                 "--queue-num",
                                                 number,
                                                 "--enable-inline",
                                                 "--rules",
                                                 "/definitely/missing/a7-rules.json",
                                                 "--log",
                                                 "-"};
        EXPECT_EQ(run_cli(args, output, errors), 1);
        EXPECT_NE(errors.str().find("rule_error:"), std::string::npos);
        EXPECT_TRUE(output.str().empty());
    }
}
}  // namespace
}  // namespace miniips
