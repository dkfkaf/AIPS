#include <gtest/gtest.h>

#include <filesystem>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <vector>

#include "fixtures/jsonl_fixtures.hpp"
#include "miniips/event_publisher.hpp"
#include "miniips/rule_loader.hpp"

namespace miniips {
namespace {
using Json = nlohmann::json;
std::vector<Json> decode_live(const std::string& value) {
    std::istringstream input(value);
    std::vector<Json> result;
    for (std::string line; std::getline(input, line);) result.push_back(Json::parse(line));
    return result;
}
TEST(LiveMetadata, StoppedIsNormalWindowEndWithoutPcapEof) {
    Engine engine;
    const auto bytes = test::tcp_packet();
    engine.inspect({bytes, static_cast<std::uint32_t>(bytes.size()), {}});
    const auto end = engine.finish(EngineEnd::Stopped);
    ASSERT_EQ(end.flows.size(), 1);
    EXPECT_EQ(end.flows[0].reason, FlowEndReason::Stopped);
    EXPECT_FALSE(end.stats.capture_complete);
    EXPECT_EQ(end.stats.tcp.memory_bytes, 0);
    EXPECT_TRUE(engine.finish().flows.empty());
    EXPECT_THROW(engine.inspect({bytes, static_cast<std::uint32_t>(bytes.size()), {}}),
                 std::logic_error);
}
TEST(LiveMetadata, LoggerUsesLiveModeForAllSevenTypes) {
    std::ostringstream output;
    EventLogger logger(output);
    for (const auto type :
         {EventType::Alert, EventType::Verdict, EventType::Flow, EventType::ParseError,
          EventType::ReassemblyWarning, EventType::Stats, EventType::EngineError}) {
        Event event;
        event.type = type;
        event.context.mode = CaptureMode::Live;
        ASSERT_TRUE(logger.write(event));
    }
    ASSERT_TRUE(logger.finish());
    for (const auto& row : decode_live(output.str())) {
        EXPECT_EQ(row["mode"], "live");
        EXPECT_FALSE(row["enforced"]);
    }
}
TEST(LiveMetadata, PipelinePublishesLiveLifecycleErrorsAndIndependentRawCounters) {
    test::TempPcap capture;
    test::write_jsonl_fixture(capture.path());
    const auto rules =
        std::filesystem::path{__FILE__}.parent_path().parent_path() / "rules/a5-demo.json";
    Engine engine({.flows = {.max_entries = 1}, .tcp_stream_bytes = 16},
                  load_rule_file(rules.string()));
    RunPublication run;
    run.mode = CaptureMode::Live;
    run.interface = "ids-test";
    run.stop_reason = "packet_limit";
    run.run_complete = true;
    run.capture = CaptureStats{true, 999, 7, 0, 32, {}};
    std::ostringstream output;
    EventLogger logger(output);
    read_pcap(capture.path().string(), [&](const PacketEnvelope& packet) {
        publish_packet(logger, engine.inspect(packet), run);
    });
    publish_finish(logger, engine.finish(EngineEnd::Stopped), run);
    ASSERT_TRUE(logger.finish());
    const auto events = decode_live(output.str());
    for (const auto& row : events) EXPECT_EQ(row["mode"], "live");
    const auto& stats = events.back();
    EXPECT_EQ(events[events.size() - 2]["reason"], "stopped");
    EXPECT_TRUE(stats["run_complete"]);
    EXPECT_FALSE(stats["capture_complete"]);
    EXPECT_EQ(stats["stop_reason"], "packet_limit");
    EXPECT_EQ(stats["capture_stats"]["ps_recv"], 999);
    EXPECT_EQ(stats["capture_stats"]["ps_drop"], 7);
    EXPECT_EQ(stats["capture_stats"]["ifdrop_availability"], "platform_dependent");
    EXPECT_EQ(stats["simulated_drop_packets"], 3);
    EXPECT_EQ(stats["actual_drop_packets"], 0);
    EXPECT_FALSE(stats.contains("log_complete"));
}
TEST(LiveMetadata, EmptyStoppedRunKeepsUnknownTimeAndUnavailableStats) {
    Engine engine;
    RunPublication run;
    run.mode = CaptureMode::Live;
    run.run_complete = true;
    run.stop_reason = "sigint";
    run.capture = CaptureStats{false, 0, 0, 0, 32, "not supported"};
    std::ostringstream output;
    EventLogger logger(output);
    publish_finish(logger, engine.finish(EngineEnd::Stopped), run);
    ASSERT_TRUE(logger.finish());
    const auto row = decode_live(output.str()).at(0);
    EXPECT_TRUE(row["timestamp"].is_null());
    EXPECT_EQ(row["capture_stats"]["status"], "unavailable");
    EXPECT_TRUE(row["capture_stats"]["ps_recv"].is_null());
}
TEST(LiveMetadata, UnopenedCaptureAndFailedRunAreNotSuccessfulInspection) {
    Engine engine;
    RunPublication run;
    run.mode = CaptureMode::Live;
    run.stop_reason = "error";
    std::ostringstream output;
    EventLogger logger(output);
    publish_finish(logger, engine.finish(EngineEnd::Aborted), run);
    ASSERT_TRUE(logger.finish());
    const auto row = decode_live(output.str()).at(0);
    EXPECT_FALSE(row["run_complete"]);
    EXPECT_EQ(row["capture_stats"]["status"], "not_open");
}
}  // namespace
}  // namespace miniips
