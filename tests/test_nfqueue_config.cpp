#include <gtest/gtest.h>

#include <stdexcept>

#include "miniips/nfqueue_source.hpp"

namespace miniips {
namespace {
TEST(NfqueueConfig, UnsafeAndInvalidConfigurationNeverOpensQueue) {
    EXPECT_THROW((NfqueueSource{QueueConfig{0, false, 1024}}), std::invalid_argument);
    EXPECT_THROW((NfqueueSource{QueueConfig{65536, true, 1024}}), std::invalid_argument);
    EXPECT_THROW((NfqueueSource{QueueConfig{0, true, 0}}), std::invalid_argument);
}
}  // namespace
}  // namespace miniips
