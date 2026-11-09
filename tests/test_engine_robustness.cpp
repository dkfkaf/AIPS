#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "fixtures/reassembly_fixtures.hpp"
#include "miniips/engine.hpp"
#include "miniips/rule_loader.hpp"

namespace miniips {
namespace {
TEST(EngineRobustness, SeededMixedEthernetAndL3InputsStayBoundedAndReleaseState) {
    EngineConfig config;
    config.flows = {16, std::chrono::milliseconds{100}};
    config.tcp_stream_bytes = 256;
    config.tcp_memory_bytes = 4096;
    config.rule_state_bytes = 1024;
    const auto rules = load_rules(R"({"rules":[{"sid":1,"enabled":true,"priority":0,
        "action":"drop","protocol":"tcp","scope":"stream","content":"HELLO",
        "message":"Robustness fixture"}]})");
    Engine engine(config, rules);
    std::uint32_t state = 0xA8202611U;
    const auto next = [&state]() {
        state = state * 1664525U + 1013904223U;
        return state;
    };
    constexpr std::uint32_t COUNT = 12000;
    for (std::uint32_t index = 0; index < COUNT; ++index) {
        std::vector<std::byte> bytes;
        if (index % 4 == 0) {
            bytes.resize(next() % 1537);
            for (auto& byte : bytes) byte = static_cast<std::byte>(next() >> 24U);
        } else if (index % 4 == 1) {
            bytes = test::tcp_segment({next(), index % 3 == 0 ? "HELLO" : "HEL",
                                       static_cast<std::uint8_t>(index % 9 == 0 ? 2 : 24),
                                       index % 5 == 0,
                                       static_cast<std::uint16_t>(10000 + next() % 64)});
        } else {
            bytes = test::udp_packet();
            test::put_be16(bytes, 34, static_cast<std::uint16_t>(10000 + next() % 64));
            if (index % 4 == 3) {
                for (unsigned int edit = 0; edit < 3; ++edit)
                    bytes[next() % bytes.size()] = static_cast<std::byte>(next() >> 24U);
                bytes.resize(next() % (bytes.size() + 1));
            }
        }
        const bool l3 = index % 2 == 0 && bytes.size() >= 14;
        const auto input = std::span<const std::byte>{bytes}.subspan(l3 ? 14U : 0U);
        const auto result =
            engine.inspect({input, static_cast<std::uint32_t>(input.size()),
                            std::chrono::microseconds{static_cast<std::int64_t>(index) * 100},
                            l3 ? PacketLayer::Ipv4 : PacketLayer::Ethernet});
        ASSERT_FALSE(result.processing_error);
        const auto stats = engine.stats();
        ASSERT_LE(stats.flow.active, config.flows.max_entries);
        ASSERT_LE(stats.tcp.memory_bytes, config.tcp_memory_bytes);
        ASSERT_LE(stats.tcp.peak_memory_bytes, config.tcp_memory_bytes);
        ASSERT_LE(stats.rules.state_bytes, config.rule_state_bytes);
    }
    const auto final = engine.finish();
    EXPECT_EQ(final.stats.packets, COUNT);
    EXPECT_GT(final.stats.parsed, 2000);
    EXPECT_GT(final.stats.skipped, 2000);
    EXPECT_EQ(final.stats.parsed + final.stats.skipped, COUNT);
    EXPECT_EQ(final.stats.tcp.memory_bytes, 0);
    EXPECT_EQ(final.stats.rules.state_bytes, 0);
    EXPECT_TRUE(final.stats.capture_complete);
}
}  // namespace
}  // namespace miniips
