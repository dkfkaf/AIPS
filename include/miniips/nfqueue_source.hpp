#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>

#include "miniips/capture_source.hpp"
#include "miniips/verdict.hpp"

namespace miniips {
struct QueueConfig {
    std::uint32_t queue_num{};
    bool enabled{};
    std::uint32_t max_pending{1024};
};
using QueueInspector = std::function<PacketResult(const PacketEnvelope&)>;
using QueueAfter = std::function<void(const PacketResult*, const InlineReceipt&)>;
// Owns one NFQUEUE binding, never edits firewall rules. After runs only after
// the current valid-ID verdict attempt. All callback exceptions are contained.
class NfqueueSource {
   public:
    explicit NfqueueSource(QueueConfig config);
    ~NfqueueSource();
    NfqueueSource(const NfqueueSource&) = delete;
    NfqueueSource& operator=(const NfqueueSource&) = delete;
    LiveStopReason run(const QueueInspector& inspect, const QueueAfter& after,
                       const StopRequest& stop = {}, std::optional<std::uint64_t> limit = {});
    bool close() noexcept;
    QueueStats stats() const noexcept;

   private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}  // namespace miniips
