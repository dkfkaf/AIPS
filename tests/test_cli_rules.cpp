#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <nlohmann/json.hpp>
#include <ostream>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "fixtures/reassembly_fixtures.hpp"
#include "miniips/cli.hpp"

namespace miniips {
namespace {
using Json = nlohmann::json;

Json rule_json() {
    return {{"sid", 1},          {"enabled", true},   {"priority", 100},    {"action", "drop"},
            {"protocol", "tcp"}, {"scope", "stream"}, {"content", "HELLO"}, {"message", "Demo"}};
}

void write_rules(const test::TempPcap& file, const Json& rules) {
    std::ofstream output(file.path().parent_path() / "rules.json", std::ios::binary);
    output << Json{{"rules", rules}}.dump();
}

int inspect(const test::TempPcap& file, const std::vector<std::string_view>& extra,
            std::ostream& output, std::ostream& errors) {
    const auto capture = file.path().string();
    const auto rules = (file.path().parent_path() / "rules.json").string();
    std::vector<std::string_view> arguments{"--mode", "pcap", "--input", capture, "--rules", rules};
    arguments.insert(arguments.end(), extra.begin(), extra.end());
    return run_cli(arguments, output, errors);
}

TEST(RulesCli, StreamDropRetransmitAndAckAreSeparateFromEventDedup) {
    test::TempPcap file;
    test::write_pcap(file.path(),
                     {test::record_at(test::tcp_segment({.sequence = 99, .flags = 0x02}), 1),
                      test::record_at(test::tcp_segment({.sequence = 100, .payload = "HEL"}), 2),
                      test::record_at(test::tcp_segment({.sequence = 103, .payload = "LO"}), 3),
                      test::record_at(test::tcp_segment({.sequence = 100, .payload = "HEL"}), 4),
                      test::record_at(test::tcp_segment({.sequence = 105, .flags = 0x10}), 5)});
    write_rules(file, Json::array({rule_json()}));
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(inspect(file, {}, output, errors), 0);
    EXPECT_TRUE(errors.str().empty());
    EXPECT_NE(output.str().find("decision packet=3 action=drop terminal_sid=1"), std::string::npos);
    EXPECT_NE(
        output.str().find("decision packet=4 action=drop terminal_sid=1 emitted=0 suppressed=1"),
        std::string::npos);
    EXPECT_NE(output.str().find("decision packet=5 action=allow terminal_sid=none"),
              std::string::npos);
    EXPECT_NE(
        output.str().find("detection_summary packets=5 events=1 suppressed=1 simulated_drops=2"),
        std::string::npos);
    EXPECT_NE(output.str().find("active=0 state_bytes=0 peak_state_bytes=8"), std::string::npos);
    EXPECT_NE(output.str().find("mode=pcap enforced=false"), std::string::npos);
    EXPECT_EQ(output.str().find("HELLO"), std::string::npos);
}

TEST(RulesCli, PacketPassPriorityAndAlertOnlyAllow) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record(test::tcp_packet())});
    auto drop = rule_json();
    drop["scope"] = "packet";
    auto pass = drop;
    pass["sid"] = 2;
    pass["priority"] = 0;
    pass["action"] = "pass";
    write_rules(file, Json::array({drop, pass}));
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(inspect(file, {}, output, errors), 0);
    EXPECT_NE(output.str().find("decision packet=1 action=allow terminal_sid=2"),
              std::string::npos);
    drop["action"] = "alert";
    write_rules(file, Json::array({drop}));
    output.str("");
    EXPECT_EQ(inspect(file, {}, output, errors), 0);
    EXPECT_NE(output.str().find("sid=1 action=alert scope=packet"), std::string::npos);
    EXPECT_NE(output.str().find("action=allow terminal_sid=none"), std::string::npos);
}

TEST(RulesCli, PacketFallbackWorksWhenFlowIsUntracked) {
    test::TempPcap file;
    test::write_pcap(file.path(),
                     {test::record(test::udp_packet()), test::record(test::tcp_packet())});
    auto rule = rule_json();
    rule["scope"] = "packet";
    write_rules(file, Json::array({rule}));
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(inspect(file, {"--max-flows", "1"}, output, errors), 0);
    EXPECT_NE(output.str().find("decision packet=2 action=drop terminal_sid=1"), std::string::npos);
    EXPECT_NE(output.str().find("rule_match packet=2 flow_id=untracked"), std::string::npos);
}

TEST(RulesCli, ExpiryReleasesWatermarksAndNewFlowEmitsAgain) {
    test::TempPcap file;
    test::write_pcap(
        file.path(),
        {test::record_at(test::tcp_segment({.sequence = 1, .payload = "HELLO"}), 0),
         test::record_at({std::byte{1}}, 120),
         test::record_at(test::tcp_segment({.sequence = 1, .payload = "HELLO"}), 121)});
    write_rules(file, Json::array({rule_json()}));
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(inspect(file, {"--rule-state-bytes", "8"}, output, errors), 0);
    EXPECT_NE(
        output.str().find("detection_summary packets=2 events=2 suppressed=0 simulated_drops=2"),
        std::string::npos);
    EXPECT_NE(output.str().find("active=0 state_bytes=0 peak_state_bytes=8"), std::string::npos);
}

TEST(RulesCli, InvalidRulesFailBeforeCaptureOutputOrOpen) {
    test::TempPcap file;
    {
        std::ofstream out(file.path().parent_path() / "rules.json");
        out << "{";
    }
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(inspect(file, {}, output, errors), 1);
    EXPECT_TRUE(output.str().empty());
    EXPECT_NE(errors.str().find("rule_error:"), std::string::npos);
    EXPECT_EQ(errors.str().find("capture_error:"), std::string::npos);
}

TEST(RulesCli, BudgetFailureIsExplicitWithoutSuccessfulSummary) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record(test::tcp_packet())});
    write_rules(file, Json::array({rule_json()}));
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(inspect(file, {"--rule-state-bytes", "7"}, output, errors), 1);
    EXPECT_NE(errors.str().find("detection_error:"), std::string::npos);
    EXPECT_EQ(output.str().find("detection_summary"), std::string::npos);
}

TEST(RulesCli, RejectsBadAndDuplicateRuleOptions) {
    test::TempPcap file;
    test::write_pcap(file.path(), {});
    write_rules(file, Json::array());
    const std::vector<std::vector<std::string_view>> cases{
        {"--rules", "again"},
        {"--rules"},
        {"--rule-state-bytes", "0"},
        {"--rule-state-bytes", "-1"},
        {"--rule-state-bytes", "+1"},
        {"--rule-state-bytes", "1x"},
        {"--rule-state-bytes", "18446744073709551616"},
        {"--rule-state-bytes", "1", "--rule-state-bytes", "2"},
        {"--rule-state-bytes"}};
    for (const auto& options : cases) {
        std::ostringstream output;
        std::ostringstream errors;
        EXPECT_EQ(inspect(file, options, output, errors), 2);
        EXPECT_TRUE(output.str().empty());
    }
}

TEST(RulesCli, MessageControlCharactersAreEscapedAndDecisionFailureIsReported) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record(test::tcp_packet())});
    auto rule = rule_json();
    rule["message"] = "line\n\x1b";
    write_rules(file, Json::array({rule}));
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(inspect(file, {}, output, errors), 0);
    EXPECT_NE(output.str().find("message=\"line\\n\\u001b\""), std::string::npos);
    EXPECT_EQ(output.str().find('\x1b'), std::string::npos);
}

class FailedDecisionBuffer : public std::stringbuf {
   protected:
    std::streamsize xsputn(const char* text, std::streamsize count) override {
        if (std::string_view{text, static_cast<std::size_t>(count)}.find("decision packet=") !=
            std::string_view::npos) {
            return 0;
        }
        return std::stringbuf::xsputn(text, count);
    }
};

TEST(RulesCli, DecisionOutputFailureIsNotSuccessfulAnalysis) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record(test::tcp_packet())});
    write_rules(file, Json::array({rule_json()}));
    FailedDecisionBuffer buffer;
    std::ostream output(&buffer);
    std::ostringstream errors;
    EXPECT_EQ(inspect(file, {}, output, errors), 1);
    EXPECT_NE(errors.str().find("Output stream failed"), std::string::npos);
}

TEST(RulesCli, DelC1AndUnicodeSeparatorsAreAsciiEscaped) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record(test::tcp_packet())});
    auto rule = rule_json();
    rule["message"] = Json::parse(R"("a\u007f\u0085\u009b\u2028\u2029b")");
    write_rules(file, Json::array({rule}));
    std::ostringstream output;
    std::ostringstream errors;
    EXPECT_EQ(inspect(file, {}, output, errors), 0);
    const auto text = output.str();
    EXPECT_NE(text.find("message=\"a\\u007f\\u0085\\u009b\\u2028\\u2029b\""), std::string::npos);
    EXPECT_TRUE(std::all_of(text.begin(), text.end(), [](unsigned char byte) {
        return byte == '\n' || (byte >= 0x20 && byte < 0x7f);
    }));
}

}  // namespace
}  // namespace miniips
