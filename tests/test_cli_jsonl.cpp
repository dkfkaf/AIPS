#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <nlohmann/json.hpp>
#include <set>
#include <sstream>
#include <streambuf>
#include <string>
#include <string_view>
#include <vector>

#include "fixtures/jsonl_fixtures.hpp"
#include "fixtures/reassembly_fixtures.hpp"
#include "miniips/cli.hpp"

namespace miniips {
namespace {
using Json = nlohmann::json;

std::vector<Json> rows(const std::string& text) {
    std::istringstream input(text);
    std::vector<Json> result;
    for (std::string line; std::getline(input, line);) {
        result.push_back(Json::parse(line));
    }
    return result;
}
std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    return {std::istreambuf_iterator<char>{input}, std::istreambuf_iterator<char>{}};
}
int run(const test::TempPcap& file, const std::vector<std::string_view>& extra,
        std::ostream& output, std::ostream& errors) {
    const auto path = file.path().string();
    std::vector<std::string_view> args{"--mode", "pcap", "--input", path};
    args.insert(args.end(), extra.begin(), extra.end());
    return run_cli(args, output, errors);
}
std::string rules_file(const test::TempPcap& file, std::string_view action = "drop") {
    const auto path = file.path().parent_path() / "rules.json";
    std::ofstream output(path);
    output << Json{{"rules", Json::array({{{"sid", 1},
                                           {"enabled", true},
                                           {"priority", 1},
                                           {"action", action},
                                           {"protocol", "tcp"},
                                           {"scope", "packet"},
                                           {"content", "HELLO"},
                                           {"message", "demo\n\x1b\x7f"}}})}};
    return path.string();
}
class FailingBuffer : public std::stringbuf {
   public:
    explicit FailingBuffer(bool flush_only = false) : flush_only_(flush_only) {}

   protected:
    std::streamsize xsputn(const char* data, std::streamsize count) override {
        return flush_only_ ? std::stringbuf::xsputn(data, count) : 0;
    }
    int sync() override { return -1; }

   private:
    bool flush_only_;
};

TEST(JsonlCli, StdoutContainsOnlyJsonAndIncludesOwnStatsCount) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record(test::tcp_packet()), test::record({})});
    std::ostringstream output, errors;
    ASSERT_EQ(run(file, {"--log", "-"}, output, errors), 0);
    const auto events = rows(output.str());
    ASSERT_FALSE(events.empty());
    EXPECT_EQ(events.back()["event_type"], "stats");
    EXPECT_EQ(events.back()["log_events_written"], events.size());
    EXPECT_EQ(events.back()["packets_total"], 2);
    EXPECT_EQ(events.back()["packets_skipped"], 1);
    EXPECT_TRUE(events.back()["capture_complete"]);
    EXPECT_FALSE(events.back().contains("log_complete"));
    EXPECT_EQ(events[1]["event_type"], "reassembly_warning");
    EXPECT_NE(errors.str().find("log_complete=1"), std::string::npos);
    std::uint64_t id = 0;
    for (const auto& event : events) {
        EXPECT_EQ(event["event_id"], ++id);
        EXPECT_EQ(event["schema_version"], 1);
        EXPECT_EQ(event["mode"], "pcap");
        EXPECT_FALSE(event["enforced"]);
    }
    EXPECT_EQ(output.str().find("HELLO"), std::string::npos);
}
TEST(JsonlCli, FileIsNewAndLegacyOutputIsPreserved) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record(test::udp_packet())});
    const auto log = (file.path().parent_path() / "events.jsonl").string();
    std::ostringstream output, errors;
    ASSERT_EQ(run(file, {"--log", log}, output, errors), 0);
    EXPECT_NE(output.str().find("pcap_summary packets=1 parsed=1 skipped=0"), std::string::npos);
    const auto events = rows(read_file(log));
    const auto verdict = std::find_if(events.begin(), events.end(), [](const Json& row) {
        return row["event_type"] == "verdict";
    });
    ASSERT_NE(verdict, events.end());
    EXPECT_EQ((*verdict)["reason"], "no_rules");
    EXPECT_EQ((*verdict)["action"], "allow");
    EXPECT_FALSE((*verdict)["rules_enabled"]);
}
TEST(JsonlCli, PreservesExistingInputRulesAndLinkTargets) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record(test::tcp_packet())});
    const auto rules = rules_file(file);
    const auto input_before = read_file(file.path());
    const auto rules_before = read_file(rules);
    const auto link = file.path().parent_path() / "link";
    std::filesystem::create_symlink(file.path(), link);
    const auto hard = file.path().parent_path() / "hard";
    std::filesystem::create_hard_link(file.path(), hard);
    for (const auto& target :
         std::vector<std::string>{file.path().string(), rules, link.string(), hard.string()}) {
        std::ostringstream output, errors;
        EXPECT_EQ(run(file, {"--rules", rules, "--log", target}, output, errors), 1);
        EXPECT_NE(errors.str().find("log_error:"), std::string::npos);
        EXPECT_TRUE(output.str().empty());
    }
    EXPECT_EQ(read_file(file.path()), input_before);
    EXPECT_EQ(read_file(rules), rules_before);
}
TEST(JsonlCli, EmptyCaptureHasUnknownTimestamp) {
    test::TempPcap file;
    test::write_pcap(file.path(), {});
    std::ostringstream output, errors;
    ASSERT_EQ(run(file, {"--log", "-"}, output, errors), 0);
    const auto events = rows(output.str());
    ASSERT_EQ(events.size(), 1);
    EXPECT_TRUE(events[0]["timestamp"].is_null());
    EXPECT_TRUE(events[0]["timestamp_us"].is_null());
    EXPECT_EQ(events[0]["timestamp_status"], "unknown");
}
TEST(JsonlCli, InputOpenFailureProducesErrorAndAbortedStats) {
    test::TempPcap file;
    std::ostringstream output, errors;
    ASSERT_EQ(run(file, {"--log", "-"}, output, errors), 1);
    const auto events = rows(output.str());
    ASSERT_EQ(events.size(), 2);
    EXPECT_EQ(events[0]["event_type"], "engine_error");
    EXPECT_EQ(events[0]["error_domain"], "capture");
    EXPECT_TRUE(events[0]["timestamp"].is_null());
    EXPECT_FALSE(events[1]["capture_complete"]);
}
TEST(JsonlCli, RulesValidateBeforeOpeningLogOrCapture) {
    test::TempPcap file;
    const auto log = (file.path().parent_path() / "new.jsonl").string();
    const auto rules = (file.path().parent_path() / "bad.json").string();
    {
        std::ofstream invalid(rules);
        invalid << "{";
    }
    std::ostringstream output, errors;
    EXPECT_EQ(run(file, {"--rules", rules, "--log", log}, output, errors), 1);
    EXPECT_NE(errors.str().find("rule_error:"), std::string::npos);
    EXPECT_FALSE(std::filesystem::exists(log));
}
TEST(JsonlCli, MissingAndDuplicateLogOptionsAreUsageErrors) {
    test::TempPcap file;
    for (const auto& extra :
         std::vector<std::vector<std::string_view>>{{"--log"}, {"--log", "-", "--log", "-"}}) {
        std::ostringstream output, errors;
        EXPECT_EQ(run(file, extra, output, errors), 2);
        EXPECT_TRUE(output.str().empty());
    }
}
TEST(JsonlCli, FailedStdoutStillComputesLaterDrops) {
    test::TempPcap file;
    test::write_pcap(file.path(),
                     {test::record(test::udp_packet()), test::record(test::tcp_packet())});
    const auto rules = rules_file(file);
    FailingBuffer buffer;
    std::ostream output(&buffer);
    std::ostringstream errors;
    EXPECT_EQ(run(file, {"--rules", rules, "--log", "-"}, output, errors), 1);
    EXPECT_NE(errors.str().find("packets=2 parsed=2"), std::string::npos);
    EXPECT_NE(errors.str().find("simulated_drops=1"), std::string::npos);
    EXPECT_NE(errors.str().find("log_complete=0"), std::string::npos);
}
TEST(JsonlCli, FinalFlushFailureCannotClaimLogCompletion) {
    test::TempPcap file;
    test::write_pcap(file.path(), {});
    FailingBuffer buffer(true);
    std::ostream output(&buffer);
    std::ostringstream errors;
    EXPECT_EQ(run(file, {"--log", "-"}, output, errors), 1);
    const auto events = rows(buffer.str());
    ASSERT_EQ(events.size(), 1);
    EXPECT_FALSE(events[0].contains("log_complete"));
    EXPECT_EQ(events[0]["log_status_at_emit"], "ok");
    EXPECT_NE(errors.str().find("log_complete=0"), std::string::npos);
}
TEST(JsonlCli, PassIsVerdictOnlyAndDropIsAlertWithEscapedMessage) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record(test::tcp_packet())});
    for (const auto action : {"pass", "drop"}) {
        const auto rules = rules_file(file, action);
        std::ostringstream output, errors;
        ASSERT_EQ(run(file, {"--rules", rules, "--log", "-"}, output, errors), 0);
        const auto events = rows(output.str());
        const auto alerts = std::count_if(events.begin(), events.end(), [](const Json& row) {
            return row["event_type"] == "alert";
        });
        EXPECT_EQ(alerts, std::string_view(action) == "drop" ? 1 : 0);
        EXPECT_EQ(events.back()["detections"], alerts);
        EXPECT_EQ(events.back()["rule_matches_emitted"], 1);
        for (const char byte : output.str()) {
            const auto value = static_cast<unsigned char>(byte);
            EXPECT_LT(value, 128);
            EXPECT_TRUE(value >= 32 || value == '\n');
        }
    }
}
TEST(JsonlCli, ProcessingBudgetErrorHasNoFalseAllowVerdict) {
    test::TempPcap file;
    test::write_pcap(file.path(), {test::record(test::tcp_packet())});
    const auto rules = rules_file(file);
    auto definition = Json::parse(read_file(rules));
    definition["rules"][0]["scope"] = "stream";
    {
        std::ofstream out(rules);
        out << definition;
    }
    std::ostringstream output, errors;
    ASSERT_EQ(
        run(file, {"--rules", rules, "--rule-state-bytes", "1", "--log", "-"}, output, errors), 1);
    const auto events = rows(output.str());
    EXPECT_EQ(std::count_if(events.begin(), events.end(),
                            [](const Json& row) { return row["event_type"] == "verdict"; }),
              0);
    EXPECT_FALSE(events.back()["capture_complete"]);
    EXPECT_EQ(events.back()["processing_errors"], 1);
}
TEST(JsonlCli, CompositeCaptureCoversAllKindsWithIndependentLogicalCounts) {
    test::TempPcap file;
    test::write_jsonl_fixture(file.path());
    const auto rules = rules_file(file);
    auto definition = Json::parse(read_file(rules));
    auto drop = definition["rules"][0];
    drop["sid"] = 3;
    drop["priority"] = 20;
    drop["scope"] = "stream";
    auto alert = drop;
    alert["sid"] = 2;
    alert["priority"] = 10;
    alert["action"] = "alert";
    auto pass = drop;
    pass["sid"] = 1;
    pass["priority"] = 0;
    pass["scope"] = "packet";
    pass["action"] = "pass";
    pass["content"] = "SAFE";
    {
        std::ofstream out(rules);
        out << Json{{"rules", Json::array({pass, alert, drop})}};
    }
    std::ostringstream output, errors;
    ASSERT_EQ(
        run(file, {"--rules", rules, "--max-flows", "1", "--tcp-stream-bytes", "16", "--log", "-"},
            output, errors),
        0);
    const auto events = rows(output.str());
    std::set<std::string> types;
    bool pass_seen = false, expired = false, conflict = false, depth = false;
    for (const auto& row : events) {
        types.insert(row["event_type"].get<std::string>());
        if (row["event_type"] == "verdict" && row["matched_action"] == "pass") pass_seen = true;
        if (row.value("reason", "") == "expired") expired = true;
        if (row.value("reason", "") == "overlap_conflict") conflict = true;
        if (row.value("reason", "") == "depth_limit") depth = true;
    }
    EXPECT_EQ(types, (std::set<std::string>{"alert", "verdict", "flow", "parse_error",
                                            "reassembly_warning", "stats", "engine_error"}));
    EXPECT_TRUE(pass_seen);
    EXPECT_TRUE(expired);
    EXPECT_TRUE(conflict);
    EXPECT_TRUE(depth);
    EXPECT_EQ(events.back()["packets_total"], 10);
    EXPECT_EQ(events.back()["packets_parsed"], 9);
    EXPECT_EQ(events.back()["rule_matches_emitted"], 3);
    EXPECT_GE(events.back()["rule_matches_suppressed"].get<int>(), 2);
    EXPECT_EQ(events.back()["detections"], 2);
    EXPECT_EQ(events.back()["alert_events_written"], 2);
    EXPECT_GE(events.back()["simulated_drop_packets"].get<int>(), 2);
    EXPECT_EQ(events.back()["actual_drop_packets"], 0);
}
}  // namespace
}  // namespace miniips
