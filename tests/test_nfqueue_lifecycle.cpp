#include <arpa/inet.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <linux/netfilter.h>
#include <unistd.h>

#include <cstdint>
#include <nlohmann/json.hpp>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "miniips/cli.hpp"
#include "miniips/nfqueue_source.hpp"

// Link-time wrappers isolate lifecycle faults without opening a real queue.
struct nfq_handle {};
struct nfq_q_handle {};
struct nfq_data {};
namespace {
struct FakeQueue {
    nfq_handle handle;
    nfq_q_handle queue;
    nfq_data packet;
    nfqnl_msg_packet_hdr header{};
    nfq_callback* callback{};
    void* context{};
    int fd{-1};
    unsigned int sends{}, destroys{};
    std::uint32_t action{};
    bool send_ok{true}, has_id{true};
};
FakeQueue state;
class NfqueueLifecycle : public testing::Test {
    void SetUp() override { state = FakeQueue{}; }
};
}  // namespace

// GNU ld --wrap requires these exact external symbol names.
// NOLINTBEGIN(bugprone-reserved-identifier)
extern "C" {
nfq_handle* __wrap_nfq_open() {
    state.fd = ::open("/dev/null", O_RDONLY | O_CLOEXEC);
    return &state.handle;
}
int __wrap_nfq_bind_pf(nfq_handle*, std::uint16_t) { return 0; }
nfq_q_handle* __wrap_nfq_create_queue(nfq_handle*, std::uint16_t, nfq_callback* callback,
                                      void* context) {
    state.callback = callback;
    state.context = context;
    return &state.queue;
}
int __wrap_nfq_set_mode(nfq_q_handle*, std::uint8_t, std::uint32_t) { return 0; }
int __wrap_nfq_set_queue_maxlen(nfq_q_handle*, std::uint32_t) { return 0; }
int __wrap_nfq_set_queue_flags(nfq_q_handle*, std::uint32_t, std::uint32_t) { return 0; }
int __wrap_nfq_fd(nfq_handle*) { return state.fd; }
int __wrap_nfq_destroy_queue(nfq_q_handle* queue) {
    ++state.destroys;
    state.callback(queue, nullptr, &state.packet, state.context);
    return 0;
}
int __wrap_nfq_close(nfq_handle*) { return ::close(state.fd); }
nfqnl_msg_packet_hdr* __wrap_nfq_get_msg_packet_hdr(nfq_data*) {
    state.header.packet_id = htonl(17);
    return state.has_id ? &state.header : nullptr;
}
int __wrap_nfq_set_verdict(nfq_q_handle*, std::uint32_t, std::uint32_t action, std::uint32_t,
                           const unsigned char*) {
    ++state.sends;
    state.action = action;
    return state.send_ok ? 0 : -1;
}
}
// NOLINTEND(bugprone-reserved-identifier)

namespace miniips {
namespace {
TEST_F(NfqueueLifecycle, SuccessfulShutdownFallbackAllowsRepeatedClose) {
    NfqueueSource source({0, true});
    EXPECT_TRUE(source.close());
    EXPECT_TRUE(source.close());
    EXPECT_EQ(state.destroys, 1);
    EXPECT_EQ(state.sends, 1);
    EXPECT_EQ(state.action, NF_DROP);
    EXPECT_EQ(source.stats().dropped, 1);
    EXPECT_EQ(source.stats().fallback_drops, 1);
    EXPECT_EQ(source.stats().failed, 0);
}
TEST_F(NfqueueLifecycle, FailedShutdownVerdictFailsRepeatedCloseWithoutRetry) {
    state.send_ok = false;
    NfqueueSource source({0, true});
    EXPECT_FALSE(source.close());
    EXPECT_FALSE(source.close());
    EXPECT_EQ(state.destroys, 1);
    EXPECT_EQ(state.sends, 1);
    EXPECT_EQ(source.stats().attempts, 1);
    EXPECT_EQ(source.stats().failed, 1);
    EXPECT_EQ(source.stats().dropped, 0);
}
TEST_F(NfqueueLifecycle, MissingShutdownIdFailsCloseWithoutInventingVerdict) {
    state.has_id = false;
    NfqueueSource source({0, true});
    EXPECT_FALSE(source.close());
    EXPECT_FALSE(source.close());
    EXPECT_EQ(source.stats().missing_ids, 1);
    EXPECT_EQ(source.stats().attempts, 0);
    EXPECT_EQ(state.sends, 0);
}
TEST_F(NfqueueLifecycle, ShutdownSendFailureChangesCliCompletionAndExitCode) {
    state.send_ok = false;
    std::ostringstream output, errors;
    const std::vector<std::string_view> args{
        "--mode", "inline", "--queue-num", "0", "--enable-inline", "--log", "-"};
    EXPECT_EQ(run_cli(args, output, errors, [] { return LiveStopReason::Requested; }), 1);
    std::istringstream lines(output.str());
    std::string line;
    nlohmann::json stats;
    while (std::getline(lines, line)) {
        const auto record = nlohmann::json::parse(line);
        if (record["event_type"] == "stats") stats = record;
    }
    ASSERT_FALSE(stats.is_null());
    EXPECT_FALSE(stats["run_complete"]);
    EXPECT_EQ(stats["stop_reason"], "error");
    EXPECT_EQ(stats["queue_stats"]["attempts"], 1);
    EXPECT_EQ(stats["queue_stats"]["failed"], 1);
    EXPECT_EQ(state.sends, 1);
}
}  // namespace
}  // namespace miniips
