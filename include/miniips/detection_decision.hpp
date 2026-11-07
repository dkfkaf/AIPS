#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "miniips/rule.hpp"

namespace miniips {

enum class DetectionAction : std::uint8_t { Allow, Drop };
struct RuleMatch {
    std::uint32_t sid{};
    RuleAction action{RuleAction::Alert};
    RuleScope scope{RuleScope::Packet};
    std::size_t end_offset{};
    std::string message;
};
struct DetectionDecision {
    DetectionAction action{DetectionAction::Allow};
    std::optional<std::uint32_t> terminal_sid;
    std::vector<RuleMatch> matches;
    std::size_t suppressed{};
    // True only when an eligible bounded stream window exists, not full coverage.
    bool stream_evaluated{};
};

}  // namespace miniips
