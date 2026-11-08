#pragma once

#include <chrono>
#include <cstdint>
#include <string_view>

#include "miniips/engine.hpp"

namespace miniips {
enum class QueueAction : std::uint8_t { Accept, Drop };
enum class VerdictReason : std::uint8_t {
    Decision,
    ParseAccept,
    ProcessingError,
    MissingPayload,
    Shutdown
};
std::string_view verdict_reason_name(VerdictReason reason) noexcept;
struct InlineReceipt {
    std::uint32_t id{};
    std::uint64_t delivery_number{};
    std::chrono::microseconds received_at{};
    QueueAction action{QueueAction::Accept};
    VerdictReason reason{VerdictReason::Decision};
    bool attempted{}, sent{}, fallback{};
};
struct QueueStats {
    std::uint64_t callbacks{}, valid_ids{}, attempts{}, accepted{}, dropped{}, failed{};
    std::uint64_t fallback_drops{}, missing_ids{}, processing_errors{}, receive_errors{},
        overflow_errors{}, close_errors{};
};
struct VerdictSender {
    void* context{};
    bool (*send)(void*, std::uint32_t, QueueAction) noexcept {};
};
// Allocation-free, single-use verdict obligation for one valid queue ID.
// Failure is never retried; destruction without submit attempts fallback Drop.
class VerdictGuard {
   public:
    VerdictGuard(std::uint32_t id, std::uint64_t number, std::chrono::microseconds at,
                 VerdictSender sender, QueueStats& stats) noexcept;
    ~VerdictGuard();
    VerdictGuard(const VerdictGuard&) = delete;
    VerdictGuard& operator=(const VerdictGuard&) = delete;
    bool submit(QueueAction action, VerdictReason reason) noexcept;
    const InlineReceipt& receipt() const noexcept;

   private:
    InlineReceipt receipt_;
    VerdictSender sender_;
    QueueStats& stats_;
};
QueueAction choose_inline_action(const PacketResult& result) noexcept;
}  // namespace miniips
