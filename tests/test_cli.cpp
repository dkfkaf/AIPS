#include "miniips/cli.hpp"

#include <gtest/gtest.h>

#include <array>
#include <sstream>
#include <string>
#include <string_view>

namespace miniips {
namespace {

TEST(Cli, HelpShowsSupportedOptions) {
    const std::array<std::string_view, 1> arguments{"--help"};
    std::ostringstream output;
    std::ostringstream errors;

    EXPECT_EQ(run_cli(arguments, output, errors), 0);
    EXPECT_NE(output.str().find("Usage:"), std::string::npos);
    EXPECT_NE(output.str().find("--help"), std::string::npos);
    EXPECT_NE(output.str().find("--version"), std::string::npos);
    EXPECT_TRUE(errors.str().empty());
}

TEST(Cli, VersionIdentifiesProgram) {
    const std::array<std::string_view, 1> arguments{"--version"};
    std::ostringstream output;
    std::ostringstream errors;

    EXPECT_EQ(run_cli(arguments, output, errors), 0);
    EXPECT_TRUE(output.str().starts_with("miniips "));
    EXPECT_GT(output.str().size(), std::string_view{"miniips "}.size());
    EXPECT_TRUE(errors.str().empty());
}

TEST(Cli, MissingOptionFails) {
    std::ostringstream output;
    std::ostringstream errors;

    EXPECT_EQ(run_cli({}, output, errors), 2);
    EXPECT_TRUE(output.str().empty());
    EXPECT_NE(errors.str().find("Usage:"), std::string::npos);
}

TEST(Cli, UnknownOptionFails) {
    const std::array<std::string_view, 1> arguments{"--unknown"};
    std::ostringstream output;
    std::ostringstream errors;

    EXPECT_EQ(run_cli(arguments, output, errors), 2);
    EXPECT_TRUE(output.str().empty());
    EXPECT_FALSE(errors.str().empty());
}

TEST(Cli, MissingPcapInputFails) {
    const std::array<std::string_view, 2> arguments{"--mode", "pcap"};
    std::ostringstream output;
    std::ostringstream errors;

    EXPECT_EQ(run_cli(arguments, output, errors), 2);
    EXPECT_TRUE(output.str().empty());
    EXPECT_NE(errors.str().find("--input"), std::string::npos);
}

TEST(Cli, ExtraArgumentsFail) {
    const std::array<std::string_view, 2> arguments{"--help", "--version"};
    std::ostringstream output;
    std::ostringstream errors;

    EXPECT_EQ(run_cli(arguments, output, errors), 2);
    EXPECT_TRUE(output.str().empty());
    EXPECT_FALSE(errors.str().empty());
}

TEST(Cli, EmptyOptionFails) {
    const std::array<std::string_view, 1> arguments{""};
    std::ostringstream output;
    std::ostringstream errors;

    EXPECT_EQ(run_cli(arguments, output, errors), 2);
    EXPECT_TRUE(output.str().empty());
    EXPECT_FALSE(errors.str().empty());
}

}  // namespace
}  // namespace miniips
