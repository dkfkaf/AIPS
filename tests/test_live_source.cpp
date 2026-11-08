#include <gtest/gtest.h>

#include <stdexcept>
#include <string>

#include "miniips/live_pcap_source.hpp"

namespace miniips {
namespace {
TEST(LiveSource, RejectsEmptyLongAndEmbeddedNulInterface) {
    EXPECT_THROW((LivePcapSource{LiveCaptureConfig{"", {}}}), std::invalid_argument);
    EXPECT_THROW((LivePcapSource{LiveCaptureConfig{std::string(16, 'x'), {}}}),
                 std::invalid_argument);
    EXPECT_THROW((LivePcapSource{LiveCaptureConfig{std::string("lo\0evil", 7), {}}}),
                 std::invalid_argument);
}
TEST(LiveSource, RejectsZeroCountBeforeActivating) {
    EXPECT_THROW((LivePcapSource{LiveCaptureConfig{"lo", 0}}), std::invalid_argument);
}
TEST(LiveSource, MissingDeviceCannotConstructAnActiveSource) {
    EXPECT_THROW((LivePcapSource{LiveCaptureConfig{"no_such_ids0", {}}}), std::runtime_error);
}
}  // namespace
}  // namespace miniips
