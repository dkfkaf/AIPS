#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>

#include "miniips/capture_source.hpp"

namespace miniips {
struct LiveCaptureConfig {
    std::string interface;
    std::optional<std::uint64_t> packet_limit;
};
struct LiveCaptureResult {
    LiveStopReason reason{LiveStopReason::Requested};
    std::uint64_t packets{};
};
// Linux, single-threaded. Owns one nonblocking Ethernet capture. Callback bytes
// are borrowed until callback return; stats must be sampled before destruction.
class LivePcapSource {
   public:
    explicit LivePcapSource(LiveCaptureConfig config);
    ~LivePcapSource();
    LivePcapSource(const LivePcapSource&) = delete;
    LivePcapSource& operator=(const LivePcapSource&) = delete;
    LiveCaptureResult run(const PacketHandler& handler, const StopRequest& stop = {});
    CaptureStats snapshot_stats() const;
    const std::string& activation_warning() const noexcept;

   private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};
}  // namespace miniips
