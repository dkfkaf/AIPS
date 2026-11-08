#include <gtest/gtest.h>

#include <chrono>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <vector>

#include "fixtures/reassembly_fixtures.hpp"
#include "miniips/event_publisher.hpp"

namespace miniips {
namespace {
using Json = nlohmann::json;
std::vector<Json> decode(const std::string& text) {
    std::istringstream input(text);
    std::vector<Json> result;
    for (std::string line; std::getline(input, line);) result.push_back(Json::parse(line));
    return result;
}
void inspect_publish(Engine& engine, EventLogger& logger, const std::vector<std::byte>& bytes,
                     std::chrono::microseconds at = {}) {
    publish_packet(logger, engine.inspect({bytes, static_cast<std::uint32_t>(bytes.size()), at}));
}
TEST(EventPublisher, ExpiryAndEofHaveWatermarkAndFirstObservedOrientation) {
    Engine engine({.flows = {.max_entries = 2, .idle_timeout = std::chrono::seconds{1}}});
    std::ostringstream output;
    EventLogger logger(output);
    inspect_publish(engine, logger, test::reverse_tcp_packet(), std::chrono::seconds{2});
    inspect_publish(engine, logger, {}, std::chrono::seconds{4});
    publish_finish(logger, engine.finish());
    ASSERT_TRUE(logger.finish());
    const auto events = decode(output.str());
    bool expired = false;
    for (const auto& row : events) {
        if (row["event_type"] == "flow" && row["reason"] == "expired") {
            expired = true;
            EXPECT_EQ(row["timestamp_us"], 4000000);
            EXPECT_EQ(row["src_port"], 8080);
            EXPECT_TRUE(row["direction"].is_null());
            EXPECT_EQ(row["first_seen_us"], 2000000);
            EXPECT_FALSE(row["reassembly"].empty());
        }
        if (row["event_type"] == "parse_error") {
            EXPECT_TRUE(row["src_ip"].is_null());
            EXPECT_EQ(row["action"], "skip");
        }
    }
    EXPECT_TRUE(expired);
}
TEST(EventPublisher, GapFilledIsInformationalAndFinalIncompleteIsSeparate) {
    Engine engine;
    std::ostringstream output;
    EventLogger logger(output);
    inspect_publish(engine, logger, test::tcp_segment({.sequence = 99, .flags = 0x02}));
    inspect_publish(engine, logger, test::tcp_segment({.sequence = 103, .payload = "LO"}));
    inspect_publish(engine, logger, test::tcp_segment({.sequence = 100, .payload = "HEL"}));
    publish_finish(logger, engine.finish());
    ASSERT_TRUE(logger.finish());
    bool resolved = false;
    for (const auto& row : decode(output.str())) {
        if (row["event_type"] == "reassembly_warning" && row["reason"] == "gap_filled") {
            resolved = true;
            EXPECT_EQ(row["severity"], "info");
            EXPECT_TRUE(row["resolved"]);
        }
    }
    EXPECT_TRUE(resolved);
    EXPECT_EQ(output.str().find("HELLO"), std::string::npos);
}
TEST(EventPublisher, FlowCapacityReportsErrorAndStillEmitsVerdict) {
    Engine engine({.flows = {.max_entries = 1}});
    std::ostringstream output;
    EventLogger logger(output);
    inspect_publish(engine, logger, test::udp_packet());
    inspect_publish(engine, logger, test::tcp_packet());
    ASSERT_TRUE(logger.finish());
    const auto events = decode(output.str());
    EXPECT_EQ(events[events.size() - 2]["event_type"], "engine_error");
    EXPECT_EQ(events.back()["event_type"], "verdict");
    EXPECT_EQ(events.back()["stream_scope"], "untracked");
    EXPECT_TRUE(events.back()["flow_id"].is_null());
}
TEST(EventPublisher, ExternalErrorIsBoundedAndMarkedTruncated) {
    std::ostringstream output;
    EventLogger logger(output);
    publish_error(logger, {}, {"capture", "read_failed", std::string(10000, 'x')});
    ASSERT_TRUE(logger.finish());
    const auto row = decode(output.str()).at(0);
    EXPECT_EQ(row["message"].get<std::string>().size(), 4096);
    EXPECT_TRUE(row["message_truncated"]);
}
TEST(EventPublisher, FailedLoggerDoesNotChangeEngineDecisionsOrLifecycle) {
    Engine engine;
    std::ostringstream output;
    EventLogger logger(output, {.max_line_bytes = 1});
    inspect_publish(engine, logger, test::tcp_packet());
    inspect_publish(engine, logger, test::reverse_tcp_packet());
    publish_finish(logger, engine.finish());
    EXPECT_FALSE(logger.finish());
    EXPECT_EQ(engine.stats().parsed, 2);
    EXPECT_EQ(engine.stats().tcp.memory_bytes, 0);
    EXPECT_EQ(logger.stats().failed_events, 1);
    EXPECT_GT(logger.stats().dropped, 0);
    EXPECT_TRUE(output.str().empty());
}
}  // namespace
}  // namespace miniips
