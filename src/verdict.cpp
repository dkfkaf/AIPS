#include "miniips/verdict.hpp"

namespace miniips {
std::string_view verdict_reason_name(VerdictReason reason) noexcept {
    switch (reason) {
        case VerdictReason::Decision:
            return "rules";
        case VerdictReason::ParseAccept:
            return "parse_error_accept";
        case VerdictReason::ProcessingError:
            return "processing_error_drop";
        case VerdictReason::MissingPayload:
            return "missing_payload_drop";
        case VerdictReason::Shutdown:
            return "shutdown_drop";
    }
    return "unknown";
}
VerdictGuard::VerdictGuard(std::uint32_t id, std::uint64_t number, std::chrono::microseconds at,
                           VerdictSender sender, QueueStats& stats) noexcept
    : receipt_{id, number, at, QueueAction::Accept, VerdictReason::Decision, false, false, false},
      sender_(sender),
      stats_(stats) {
    ++stats_.valid_ids;
}
VerdictGuard::~VerdictGuard() {
    if (!receipt_.attempted) submit(QueueAction::Drop, VerdictReason::Shutdown);
}
bool VerdictGuard::submit(QueueAction action, VerdictReason reason) noexcept {
    if (receipt_.attempted) return receipt_.sent;
    receipt_.attempted = true;
    receipt_.action = action;
    receipt_.reason = reason;
    receipt_.fallback = reason != VerdictReason::Decision && reason != VerdictReason::ParseAccept;
    ++stats_.attempts;
    receipt_.sent = sender_.send && sender_.send(sender_.context, receipt_.id, action);
    if (!receipt_.sent)
        ++stats_.failed;
    else if (action == QueueAction::Accept)
        ++stats_.accepted;
    else {
        ++stats_.dropped;
        stats_.fallback_drops += receipt_.fallback ? 1U : 0U;
    }
    return receipt_.sent;
}
const InlineReceipt& VerdictGuard::receipt() const noexcept { return receipt_; }
QueueAction choose_inline_action(const PacketResult& result) noexcept {
    if (result.processing_error) return QueueAction::Drop;
    return result.decision && result.decision->action == DetectionAction::Drop
               ? QueueAction::Drop
               : QueueAction::Accept;
}
}  // namespace miniips
