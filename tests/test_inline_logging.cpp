#include <gtest/gtest.h>

#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <vector>

#include "fixtures/packet_fixtures.hpp"
#include "miniips/event_publisher.hpp"

namespace miniips {
namespace {
using Json = nlohmann::json;
std::vector<Json> decode_inline(const std::string& value) {
    std::istringstream input(value);
    std::vector<Json> rows;
    for (std::string line; std::getline(input, line);) rows.push_back(Json::parse(line));
    return rows;
}
TEST(InlineLogging, ReceiptIsOnlyVerdictAndUsesReceiveTime) {
    Engine engine;
    const auto bytes = test::tcp_packet();
    const auto result = engine.inspect({bytes, static_cast<std::uint32_t>(bytes.size()), {}});
    RunPublication run;
    run.mode = CaptureMode::Inline;
    run.queue_num = 0;
    std::ostringstream output;
    EventLogger logger(output);
    InlineReceipt receipt{7,    1,    {},   QueueAction::Accept, VerdictReason::Decision,
                          true, true, false};
    publish_packet(logger, result, run);
    publish_inline_verdict(logger, &result, receipt, run);
    ASSERT_TRUE(logger.finish());
    unsigned int verdicts = 0;
    for (const auto& row : decode_inline(output.str())) {
        EXPECT_EQ(row["mode"], "inline");
        EXPECT_EQ(row["timestamp_status"], "receive");
        if (row["event_type"] == "verdict") {
            ++verdicts;
            EXPECT_TRUE(row["enforced"]);
            EXPECT_EQ(row["queue_packet_id"], 7);
            EXPECT_EQ(row["action"], "allow");
        } else
            EXPECT_FALSE(row["enforced"]);
    }
    EXPECT_EQ(verdicts, 1);
}
TEST(InlineLogging, ParseFailureStillRecordsActualAcceptWithoutInspectionClaim) {
    Engine engine;
    const auto result = engine.inspect({{}, 0, {}, PacketLayer::Ipv4});
    RunPublication run;
    run.mode = CaptureMode::Inline;
    std::ostringstream output;
    EventLogger logger(output);
    publish_packet(logger, result, run);
    publish_inline_verdict(
        logger, &result,
        {8, 1, {}, QueueAction::Accept, VerdictReason::ParseAccept, true, true, false}, run);
    ASSERT_TRUE(logger.finish());
    const auto rows = decode_inline(output.str());
    ASSERT_EQ(rows.size(), 2);
    EXPECT_EQ(rows[0]["event_type"], "parse_error");
    EXPECT_EQ(rows[1]["action"], "allow");
    EXPECT_EQ(rows[1]["inspection_status"], "unsupported");
    EXPECT_TRUE(rows[1]["enforced"]);
    EXPECT_TRUE(rows[1]["src_ip"].is_null());
}
TEST(InlineLogging, SendFailureIsNotEnforcedAndActualCountersExcludeIt) {
    RunPublication run;
    run.mode = CaptureMode::Inline;
    QueueStats counters;
    counters.attempts = 1;
    counters.failed = 1;
    run.queue = counters;
    std::ostringstream output;
    EventLogger logger(output);
    publish_inline_verdict(
        logger, nullptr,
        {9, 1, {}, QueueAction::Drop, VerdictReason::ProcessingError, true, false, true}, run);
    Engine engine;
    publish_finish(logger, engine.finish(EngineEnd::Aborted), run);
    ASSERT_TRUE(logger.finish());
    const auto rows = decode_inline(output.str());
    EXPECT_FALSE(rows[0]["enforced"]);
    EXPECT_EQ(rows[0]["reason"], "verdict_send_failed");
    EXPECT_TRUE(rows[0]["packet_number"].is_null());
    EXPECT_EQ(rows.back()["actual_drop_packets"], 0);
    EXPECT_EQ(rows.back()["queue_stats"]["failed"], 1);
}
TEST(InlineLogging, ActualAndLogicalDropCountersAreSeparate) {
    RunPublication run;
    run.mode = CaptureMode::Inline;
    QueueStats counters;
    counters.dropped = 2;
    counters.accepted = 3;
    counters.fallback_drops = 1;
    run.queue = counters;
    FinishResult result;
    result.stats.rules.drops = 1;
    std::ostringstream output;
    EventLogger logger(output);
    publish_finish(logger, result, run);
    ASSERT_TRUE(logger.finish());
    const auto row = decode_inline(output.str()).at(0);
    EXPECT_EQ(row["simulated_drop_packets"], 0);
    EXPECT_EQ(row["logical_rule_drop_packets"], 1);
    EXPECT_EQ(row["actual_drop_packets"], 2);
    EXPECT_EQ(row["actual_accept_packets"], 3);
    EXPECT_EQ(row["fallback_drop_packets"], 1);
}
TEST(InlineLogging, ForgedEnforcementInPassiveModeIsRejected) {
    std::ostringstream output;
    EventLogger logger(output);
    Event event;
    event.type = EventType::Verdict;
    event.context.enforced = true;
    EXPECT_FALSE(logger.write(event));
    EXPECT_TRUE(output.str().empty());
}
}  // namespace
}  // namespace miniips
