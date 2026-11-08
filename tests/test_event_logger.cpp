#include <gtest/gtest.h>
#include <sys/stat.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <limits>
#include <locale>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>

#include "miniips/event_logger.hpp"
#include "pcap_fixture.hpp"

namespace miniips {
namespace {

Event sample_event() {
    Event event;
    event.type = EventType::Alert;
    event.action = EventAction::Drop;
    event.message = "Demo match";
    event.sid = 1001;
    event.context.captured_at = std::chrono::microseconds{1250000};
    event.context.packet_number = 7;
    event.context.flow_id = std::numeric_limits<std::uint64_t>::max();
    event.context.source = FlowEndpoint{0xC0000201U, 12345};
    event.context.destination = FlowEndpoint{0xC6336402U, 8080};
    event.context.protocol = TransportProtocol::Tcp;
    event.context.direction = FlowDirection::Forward;
    return event;
}

TEST(EventLogger, WritesCommonSchemaAndExactUnsignedIds) {
    std::ostringstream output;
    EventLogger logger(output);
    EXPECT_TRUE(logger.write(sample_event()));
    EXPECT_TRUE(logger.finish());
    const auto text = output.str();
    ASSERT_FALSE(text.empty());
    EXPECT_EQ(text.back(), '\n');
    const auto row = nlohmann::json::parse(text);
    EXPECT_EQ(row.at("schema_version"), 1);
    EXPECT_EQ(row.at("event_type"), "alert");
    EXPECT_EQ(row.at("event_id"), 1);
    EXPECT_EQ(row.at("timestamp"), "1970-01-01T00:00:01.250000Z");
    EXPECT_EQ(row.at("timestamp_us"), 1250000);
    EXPECT_EQ(row.at("flow_id").get<std::uint64_t>(), std::numeric_limits<std::uint64_t>::max());
    EXPECT_EQ(row.at("src_ip"), "192.0.2.1");
    EXPECT_EQ(row.at("dst_port"), 8080);
    EXPECT_EQ(row.at("direction"), "fwd");
    EXPECT_EQ(row.at("action"), "drop");
    EXPECT_EQ(row.at("mode"), "pcap");
    EXPECT_EQ(row.at("enforced"), false);
    EXPECT_EQ(logger.stats().written, 1);
    EXPECT_EQ(logger.stats().alert_written, 1);
}

TEST(EventLogger, MissingAndOutOfRangeTimesDoNotInventClockValues) {
    std::ostringstream output;
    EventLogger logger(output);
    auto event = sample_event();
    event.context = {};
    logger.write(event);
    std::istringstream first(output.str());
    std::string line;
    std::getline(first, line);
    const auto unknown = nlohmann::json::parse(line);
    for (const char* key : {"timestamp", "timestamp_us", "flow_id", "packet_number", "src_ip",
                            "src_port", "dst_ip", "dst_port", "protocol", "direction"}) {
        EXPECT_TRUE(unknown.at(key).is_null()) << key;
    }
    event.context.captured_at = std::chrono::microseconds{std::numeric_limits<std::int64_t>::max()};
    logger.write(event);
    logger.finish();
    std::istringstream all(output.str());
    std::getline(all, line);
    std::getline(all, line);
    const auto extreme = nlohmann::json::parse(line);
    EXPECT_TRUE(extreme.at("timestamp").is_null());
    EXPECT_EQ(extreme.at("timestamp_status"), "out_of_range");
    EXPECT_EQ(extreme.at("timestamp_us").get<std::int64_t>(),
              std::numeric_limits<std::int64_t>::max());
}

TEST(EventLogger, EscapesControlsInvalidUtf8AndTruncatesMessage) {
    std::ostringstream output;
    EventLogger logger(output);
    auto event = sample_event();
    event.message =
        nlohmann::json::parse(R"("a\u007f\u0085\u009b\u2028\u2029\n\u001bb")").get<std::string>();
    event.message += '\xff';
    EXPECT_TRUE(logger.write(event));
    event.message = std::string(5000, 'X');
    EXPECT_TRUE(logger.write(event));
    EXPECT_TRUE(logger.finish());
    const auto text = output.str();
    for (const char value : text) {
        const auto byte = static_cast<unsigned char>(value);
        EXPECT_TRUE(byte == '\n' || (byte >= 0x20 && byte < 0x7f));
    }
    std::istringstream lines(text);
    std::string first;
    std::string second;
    std::getline(lines, first);
    std::getline(lines, second);
    EXPECT_NE(first.find("\\u007f"), std::string::npos);
    EXPECT_TRUE(nlohmann::json::parse(first).is_object());
    const auto truncated = nlohmann::json::parse(second);
    EXPECT_EQ(truncated.at("message").get<std::string>().size(), 4096);
    EXPECT_EQ(truncated.at("message_truncated"), true);
}

TEST(EventLogger, RejectsReservedFieldOverridesAndLatchesFailure) {
    std::ostringstream output;
    EventLogger logger(output);
    auto event = sample_event();
    event.fields["enforced"] = true;
    EXPECT_FALSE(logger.write(event));
    EXPECT_FALSE(logger.write(sample_event()));
    EXPECT_FALSE(logger.finish());
    EXPECT_TRUE(output.str().empty());
    EXPECT_EQ(logger.stats().attempted, 2);
    EXPECT_EQ(logger.stats().failed_events, 1);
    EXPECT_EQ(logger.stats().dropped, 1);
}

TEST(EventLogger, LineLimitFailureNeverAppendsLaterEvents) {
    std::ostringstream output;
    EventLogger logger(output, {.max_line_bytes = 64});
    EXPECT_FALSE(logger.write(sample_event()));
    EXPECT_TRUE(logger.failed());
    EXPECT_FALSE(logger.write(sample_event()));
    EXPECT_TRUE(output.str().empty());
    EXPECT_EQ(logger.stats().failed_events, 1);
    EXPECT_EQ(logger.stats().dropped, 1);
}

class PartialBuffer : public std::stringbuf {
   protected:
    std::streamsize xsputn(const char* text, std::streamsize count) override {
        return std::stringbuf::xsputn(text, count / 2);
    }
};

TEST(EventLogger, PartialStreamWriteLeavesOnlyOneIncompleteRecord) {
    PartialBuffer buffer;
    std::ostream output(&buffer);
    EventLogger logger(output);
    EXPECT_FALSE(logger.write(sample_event()));
    const auto partial = buffer.str();
    EXPECT_FALSE(partial.empty());
    EXPECT_FALSE(logger.write(sample_event()));
    EXPECT_EQ(buffer.str(), partial);
    EXPECT_FALSE(logger.finish());
}

class FailedFlushBuffer : public std::stringbuf {
   public:
    int sync() override { return -1; }
};

TEST(EventLogger, FlushFailureIsKnownOnlyAfterFinishAndFinishIsIdempotent) {
    FailedFlushBuffer buffer;
    std::ostream output(&buffer);
    EventLogger logger(output);
    EXPECT_TRUE(logger.write(sample_event()));
    EXPECT_FALSE(logger.failed());
    EXPECT_FALSE(logger.finish());
    EXPECT_FALSE(logger.finish());
    EXPECT_EQ(logger.stats().written, 1);
    EXPECT_EQ(logger.stats().io_errors, 1);
    EXPECT_TRUE(logger.stats().finished);
}

TEST(EventLogger, StreamExceptionsNeverEscapeWriteOrFinish) {
    std::ostringstream output;
    output.setstate(std::ios::badbit);
    EventLogger logger(output);
    EXPECT_FALSE(logger.write(sample_event()));
    EXPECT_FALSE(logger.finish());
    EXPECT_TRUE(logger.failed());
}

TEST(EventLogger, FileIsExclusivePrivateAndClosedExplicitly) {
    test::TempPcap temp;
    const auto path = temp.path().parent_path() / "events.jsonl";
    EventLogger logger(path);
    EXPECT_TRUE(logger.write(sample_event()));
    EXPECT_TRUE(logger.finish());
    EXPECT_TRUE(logger.finish());
    struct stat status {};
    ASSERT_EQ(::stat(path.c_str(), &status), 0);
    EXPECT_EQ(status.st_mode & 0777U, 0600U);
    std::ifstream input(path);
    std::string text((std::istreambuf_iterator<char>(input)), {});
    EXPECT_EQ(nlohmann::json::parse(text).at("sid"), 1001);
    EXPECT_THROW(EventLogger{path}, LogOpenError);
    EXPECT_FALSE(logger.write(sample_event()));
}

TEST(EventLogger, ExistingInputAndSymlinkHardlinkArePreserved) {
    test::TempPcap temp;
    {
        std::ofstream original(temp.path());
        original << "preserve";
    }
    const auto symlink = temp.path().parent_path() / "symlink.jsonl";
    const auto hardlink = temp.path().parent_path() / "hardlink.jsonl";
    std::filesystem::create_symlink(temp.path(), symlink);
    std::filesystem::create_hard_link(temp.path(), hardlink);
    EXPECT_THROW(EventLogger{temp.path()}, LogOpenError);
    EXPECT_THROW(EventLogger{symlink}, LogOpenError);
    EXPECT_THROW(EventLogger{hardlink}, LogOpenError);
    std::ifstream input(temp.path());
    std::string text;
    input >> text;
    EXPECT_EQ(text, "preserve");
}

TEST(EventLogger, MissingParentAndZeroLimitAreRejected) {
    test::TempPcap temp;
    EXPECT_THROW(EventLogger{temp.path() / "missing" / "events.jsonl"}, LogOpenError);
    std::ostringstream output;
    EXPECT_THROW((EventLogger{output, {.max_line_bytes = 0}}), std::invalid_argument);
}

class GroupedDigits : public std::numpunct<char> {
   protected:
    char do_thousands_sep() const override { return ','; }
    std::string do_grouping() const override { return "\3"; }
};

TEST(EventLogger, TimestampIsIndependentOfGlobalNumberLocale) {
    const auto original = std::locale();
    std::locale::global(std::locale(original, new GroupedDigits));
    std::ostringstream output;
    EventLogger logger(output);
    const bool success = logger.write(sample_event());
    logger.finish();
    std::locale::global(original);
    EXPECT_TRUE(success);
    const auto row = nlohmann::json::parse(output.str());
    EXPECT_EQ(row.at("timestamp"), "1970-01-01T00:00:01.250000Z");
}

}  // namespace
}  // namespace miniips
