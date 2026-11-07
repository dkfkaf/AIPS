#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace miniips {

enum class RuleAction : std::uint8_t { Alert, Drop, Pass };
enum class RuleScope : std::uint8_t { Packet, Stream };
enum class RuleProtocol : std::uint8_t { Tcp, Udp, Any };

struct Rule {
    std::uint32_t sid{};
    bool enabled{};
    std::int32_t priority{};
    RuleAction action{RuleAction::Alert};
    RuleProtocol protocol{RuleProtocol::Tcp};
    RuleScope scope{RuleScope::Packet};
    std::optional<std::uint16_t> src_port;
    std::optional<std::uint16_t> dst_port;
    std::string content;
    std::string message;
    std::vector<std::size_t> failure;
    std::size_t stream_index{std::numeric_limits<std::size_t>::max()};
};

// Only an empty set or the validated loader can construct the owned collection.
// Returned const views live as long as this unchanged RuleSet.
class RuleSet {
   public:
    RuleSet() = default;
    std::span<const Rule> rules() const noexcept { return rules_; }
    std::size_t stream_rule_count() const noexcept { return stream_count_; }

   private:
    friend RuleSet load_rules(std::string_view text);
    RuleSet(std::vector<Rule> rules, std::size_t streams)
        : rules_(std::move(rules)), stream_count_(streams) {}
    std::vector<Rule> rules_;
    std::size_t stream_count_{};
};

}  // namespace miniips
