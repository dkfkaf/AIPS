#pragma once

#include <filesystem>
#include <stdexcept>
#include <string_view>

#include "miniips/rule.hpp"

namespace miniips {

class RuleLoadError : public std::runtime_error {
   public:
    using std::runtime_error::runtime_error;
};

// Strict, atomic loading; no partially valid set escapes on error.
RuleSet load_rules(std::string_view text);
RuleSet load_rule_file(const std::filesystem::path& path);

}  // namespace miniips
