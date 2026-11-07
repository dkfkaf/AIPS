#include "miniips/rule_loader.hpp"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <fstream>
#include <limits>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <unordered_set>
#include <utility>
#include <vector>

namespace miniips {
namespace {
using Json = nlohmann::json;
constexpr std::size_t MAX_FILE_BYTES = 1048576;
constexpr std::size_t MAX_RULES = 1024;

std::int64_t integer(const Json& value, std::int64_t minimum, std::int64_t maximum,
                     std::string_view field) {
    if (!value.is_number_integer() ||
        (value.is_number_unsigned() &&
         value.get<std::uint64_t>() > static_cast<std::uint64_t>(maximum))) {
        throw RuleLoadError(std::string{field} + " must be an integer in range.");
    }
    const auto result = value.get<std::int64_t>();
    if (result < minimum || result > maximum) {
        throw RuleLoadError(std::string{field} + " must be an integer in range.");
    }
    return result;
}

std::string string_field(const Json& rule, const char* field, std::size_t maximum) {
    const auto& value = rule.at(field);
    if (!value.is_string()) {
        throw RuleLoadError(std::string{field} + " must be a string.");
    }
    auto text = value.get<std::string>();
    if (text.empty() || text.size() > maximum) {
        throw RuleLoadError(std::string{field} + " length is outside its limit.");
    }
    return text;
}

Rule parse_rule(const Json& item) {
    constexpr std::array<std::string_view, 8> REQUIRED{
        "sid", "enabled", "priority", "action", "protocol", "scope", "content", "message"};
    if (!item.is_object()) {
        throw RuleLoadError("Rule must be an object.");
    }
    for (const auto name : REQUIRED) {
        if (!item.contains(name)) {
            throw RuleLoadError("Missing field: " + std::string{name});
        }
    }
    for (const auto& [key, value] : item.items()) {
        static_cast<void>(value);
        if (std::find(REQUIRED.begin(), REQUIRED.end(), key) == REQUIRED.end() &&
            key != "src_port" && key != "dst_port") {
            throw RuleLoadError("Unknown rule field.");
        }
    }
    Rule rule;
    rule.sid = static_cast<std::uint32_t>(
        integer(item.at("sid"), 1, std::numeric_limits<std::uint32_t>::max(), "sid"));
    rule.priority = static_cast<std::int32_t>(
        integer(item.at("priority"), std::numeric_limits<std::int32_t>::min(),
                std::numeric_limits<std::int32_t>::max(), "priority"));
    if (!item.at("enabled").is_boolean()) {
        throw RuleLoadError("enabled must be boolean.");
    }
    rule.enabled = item.at("enabled").get<bool>();
    const auto action = string_field(item, "action", 5);
    if (action == "alert") {
        rule.action = RuleAction::Alert;
    } else if (action == "drop") {
        rule.action = RuleAction::Drop;
    } else if (action == "pass") {
        rule.action = RuleAction::Pass;
    } else {
        throw RuleLoadError("Unsupported action.");
    }
    const auto protocol = string_field(item, "protocol", 3);
    if (protocol == "tcp") {
        rule.protocol = RuleProtocol::Tcp;
    } else if (protocol == "udp") {
        rule.protocol = RuleProtocol::Udp;
    } else if (protocol == "any") {
        rule.protocol = RuleProtocol::Any;
    } else {
        throw RuleLoadError("Unsupported protocol.");
    }
    const auto scope = string_field(item, "scope", 6);
    if (scope == "packet") {
        rule.scope = RuleScope::Packet;
    } else if (scope == "stream" && rule.protocol == RuleProtocol::Tcp) {
        rule.scope = RuleScope::Stream;
    } else {
        throw RuleLoadError("scope must be packet, or stream with tcp only.");
    }
    for (const char* name : {"src_port", "dst_port"}) {
        if (item.contains(name)) {
            const auto port = static_cast<std::uint16_t>(integer(item.at(name), 0, 65535, name));
            (std::string_view{name} == "src_port" ? rule.src_port : rule.dst_port) = port;
        }
    }
    rule.content = string_field(item, "content", 4096);
    if (!std::all_of(rule.content.begin(), rule.content.end(),
                     [](unsigned char byte) { return byte >= 0x20 && byte <= 0x7e; })) {
        throw RuleLoadError("content must contain printable ASCII only.");
    }
    rule.message = string_field(item, "message", 1024);
    rule.failure.resize(rule.content.size());
    for (std::size_t index = 1, matched = 0; index < rule.content.size(); ++index) {
        while (matched != 0 && rule.content[index] != rule.content[matched]) {
            matched = rule.failure[matched - 1];
        }
        if (rule.content[index] == rule.content[matched]) {
            ++matched;
        }
        rule.failure[index] = matched;
    }
    return rule;
}

}  // namespace

RuleSet load_rules(std::string_view text) {
    if (text.size() > MAX_FILE_BYTES) {
        throw RuleLoadError("Rule file exceeds 1 MiB.");
    }
    // NUL is not valid JSON whitespace; some parser input adapters treat it as EOF.
    if (text.find('\0') != std::string_view::npos) {
        throw RuleLoadError("Unexpected NUL in JSON source.");
    }
    try {
        std::vector<std::unordered_set<std::string>> keys;
        const auto guard = [&](int depth, Json::parse_event_t event, Json& parsed) {
            if (depth > 8) {
                throw RuleLoadError("JSON nesting exceeds depth 8.");
            }
            if (event == Json::parse_event_t::object_start) {
                keys.emplace_back();
            } else if (event == Json::parse_event_t::key) {
                if (!keys.back().insert(parsed.get<std::string>()).second) {
                    throw RuleLoadError("Duplicate JSON object key.");
                }
            } else if (event == Json::parse_event_t::object_end) {
                keys.pop_back();
            }
            return true;
        };
        const auto root = Json::parse(text.begin(), text.end(), guard);
        if (!root.is_object() || root.size() != 1 || !root.contains("rules") ||
            !root.at("rules").is_array() || root.at("rules").size() > MAX_RULES) {
            throw RuleLoadError("Expected one rules array with at most 1024 entries.");
        }
        std::vector<Rule> rules;
        std::unordered_set<std::uint32_t> sids;
        for (const auto& item : root.at("rules")) {
            try {
                auto rule = parse_rule(item);
                if (!sids.insert(rule.sid).second) {
                    throw RuleLoadError("Duplicate sid.");
                }
                rules.push_back(std::move(rule));
            } catch (const RuleLoadError& error) {
                throw RuleLoadError("Rule index " + std::to_string(rules.size()) + ": " +
                                    error.what());
            }
        }
        std::sort(rules.begin(), rules.end(), [](const Rule& lhs, const Rule& rhs) {
            return lhs.priority != rhs.priority ? lhs.priority < rhs.priority : lhs.sid < rhs.sid;
        });
        std::size_t stream_count = 0;
        for (auto& rule : rules) {
            if (rule.enabled && rule.scope == RuleScope::Stream) {
                rule.stream_index = stream_count++;
            }
        }
        return RuleSet{std::move(rules), stream_count};
    } catch (const Json::exception&) {
        throw RuleLoadError("Invalid JSON syntax, type, encoding or numeric range.");
    }
}

RuleSet load_rule_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input) {
        throw RuleLoadError("Cannot open rule file.");
    }
    std::string text(MAX_FILE_BYTES + 1, '\0');
    input.read(text.data(), static_cast<std::streamsize>(text.size()));
    if (input.bad()) {
        throw RuleLoadError("Cannot read rule file.");
    }
    text.resize(static_cast<std::size_t>(input.gcount()));
    return load_rules(text);
}

}  // namespace miniips
