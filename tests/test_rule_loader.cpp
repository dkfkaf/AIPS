#include <gtest/gtest.h>

#include <cstddef>
#include <fstream>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "miniips/rule_loader.hpp"
#include "pcap_fixture.hpp"

namespace miniips {
namespace {
using Json = nlohmann::json;

Json valid_rule() {
    return {{"sid", 1},          {"enabled", true},   {"priority", 100},    {"action", "alert"},
            {"protocol", "tcp"}, {"scope", "stream"}, {"content", "HELLO"}, {"message", "Demo"}};
}

RuleSet load_one(const Json& rule) {
    return load_rules(Json{{"rules", Json::array({rule})}}.dump());
}

TEST(RuleLoader, LoadsAndSortsValidatedRules) {
    auto first = valid_rule();
    first["sid"] = 3;
    auto second = valid_rule();
    second["sid"] = 2;
    second["priority"] = -1;
    auto third = second;
    third["sid"] = 1;
    const auto rules = load_rules(Json{{"rules", Json::array({first, second, third})}}.dump());
    ASSERT_EQ(rules.rules().size(), 3);
    EXPECT_EQ(rules.rules()[0].sid, 1);
    EXPECT_EQ(rules.rules()[1].sid, 2);
    EXPECT_EQ(rules.rules()[2].sid, 3);
    EXPECT_EQ(rules.stream_rule_count(), 3);
    EXPECT_EQ(rules.rules()[0].content, "HELLO");
    EXPECT_EQ(rules.rules()[0].failure, (std::vector<std::size_t>{0, 0, 0, 0, 0}));
    EXPECT_TRUE(load_rules(R"({"rules":[]})").rules().empty());
}

TEST(RuleLoader, RejectsMissingUnknownAndWrongTypesEvenWhenDisabled) {
    const auto base = valid_rule();
    for (const auto& [key, ignored] : base.items()) {
        static_cast<void>(ignored);
        auto missing = base;
        missing.erase(key);
        EXPECT_THROW(load_one(missing), RuleLoadError) << key;
        auto wrong = base;
        wrong[key] = nullptr;
        EXPECT_THROW(load_one(wrong), RuleLoadError) << key;
    }
    auto extra = base;
    extra["dst_ip"] = "ignored?";
    EXPECT_THROW(load_one(extra), RuleLoadError);
    extra = base;
    extra["enabled"] = false;
    extra["content"] = "";
    EXPECT_THROW(load_one(extra), RuleLoadError);
    EXPECT_THROW(load_rules(R"({"rules":[],"extra":1})"), RuleLoadError);
    EXPECT_THROW(load_rules("[]"), RuleLoadError);
    EXPECT_THROW(load_rules(R"({"rules":{}})"), RuleLoadError);
}

TEST(RuleLoader, EnforcesIntegerAndPortBoundaries) {
    for (const Json& value : std::vector<Json>{0, -1, 1.0, true, "1", 4294967296ULL}) {
        auto rule = valid_rule();
        rule["sid"] = value;
        EXPECT_THROW(load_one(rule), RuleLoadError) << value;
    }
    for (const Json& value : std::vector<Json>{-2147483649LL, 2147483648ULL, 1.0, true}) {
        auto rule = valid_rule();
        rule["priority"] = value;
        EXPECT_THROW(load_one(rule), RuleLoadError) << value;
    }
    auto rule = valid_rule();
    rule["sid"] = 4294967295ULL;
    rule["priority"] = -2147483648LL;
    rule["src_port"] = 0;
    rule["dst_port"] = 65535;
    auto set = load_one(rule);
    EXPECT_EQ(set.rules()[0].sid, 4294967295U);
    EXPECT_EQ(set.rules()[0].src_port, 0);
    EXPECT_EQ(set.rules()[0].dst_port, 65535);
    for (const char* port : {"src_port", "dst_port"}) {
        for (const Json& value : std::vector<Json>{-1, 65536, 1.0, true, "80", nullptr}) {
            rule[port] = value;
            EXPECT_THROW(load_one(rule), RuleLoadError) << port << ':' << value;
        }
        rule.erase(port);
    }
}

TEST(RuleLoader, RejectsEnumsAndInvalidStreamProtocol) {
    for (const char* protocol : {"udp", "any", "TCP", "icmp"}) {
        auto rule = valid_rule();
        rule["protocol"] = protocol;
        EXPECT_THROW(load_one(rule), RuleLoadError);
    }
    auto rule = valid_rule();
    rule["scope"] = "packet";
    for (const char* protocol : {"tcp", "udp", "any"}) {
        rule["protocol"] = protocol;
        for (const char* action : {"alert", "drop", "pass"}) {
            rule["action"] = action;
            EXPECT_NO_THROW(load_one(rule));
        }
    }
    rule["action"] = "allow";
    EXPECT_THROW(load_one(rule), RuleLoadError);
    rule = valid_rule();
    rule["scope"] = "STREAM";
    EXPECT_THROW(load_one(rule), RuleLoadError);
}

TEST(RuleLoader, RejectsDuplicateSidAndObjectKeys) {
    auto disabled = valid_rule();
    disabled["enabled"] = false;
    EXPECT_THROW(load_rules(Json{{"rules", Json::array({valid_rule(), disabled})}}.dump()),
                 RuleLoadError);
    EXPECT_THROW(load_rules(R"({"rules":[],"rules":[]})"), RuleLoadError);
    auto text = Json{{"rules", Json::array({valid_rule()})}}.dump();
    text.insert(text.find("\"sid\""), "\"sid\":2,");
    EXPECT_THROW(load_rules(text), RuleLoadError);
}

TEST(RuleLoader, LimitsAsciiContentAndUtf8Message) {
    auto rule = valid_rule();
    for (const std::string& value : {std::string{}, std::string{"\n"}, std::string(1, '\x7f'),
                                     std::string{"한글"}, std::string(4097, 'A')}) {
        rule["content"] = value;
        EXPECT_THROW(load_one(rule), RuleLoadError);
    }
    rule["content"] = std::string(4096, 'A');
    rule["message"] = std::string(1024, 'M');
    EXPECT_NO_THROW(load_one(rule));
    rule["message"] = std::string(1025, 'M');
    EXPECT_THROW(load_one(rule), RuleLoadError);
    rule["message"] = "";
    EXPECT_THROW(load_one(rule), RuleLoadError);
    rule["message"] = "한글\n\x1b";
    EXPECT_NO_THROW(load_one(rule));
    EXPECT_THROW(load_rules(std::string("{\"rules\":[\"") + '\xff' + "\"]}"), RuleLoadError);
}

TEST(RuleLoader, RejectsMalformedOversizeAndDeepJson) {
    for (const std::string text : {"", "{", "{\"rules\":[]} false", "/*x*/{\"rules\":[]}"}) {
        EXPECT_THROW(load_rules(text), RuleLoadError);
    }
    EXPECT_THROW(load_rules(std::string(1048577, ' ')), RuleLoadError);
    EXPECT_THROW(load_rules(std::string(1000, '[') + "0" + std::string(1000, ']')), RuleLoadError);
    Json many = Json::array();
    for (unsigned int sid = 1; sid <= 1025; ++sid) {
        auto rule = valid_rule();
        rule["sid"] = sid;
        many.push_back(rule);
    }
    EXPECT_THROW(load_rules(Json{{"rules", many}}.dump()), RuleLoadError);
    many.erase(many.size() - 1);
    EXPECT_EQ(load_rules(Json{{"rules", many}}.dump()).rules().size(), 1024);
}

TEST(RuleLoader, BoundedFileReadAndNoPartialLoad) {
    test::TempPcap file;
    EXPECT_THROW(load_rule_file(file.path()), RuleLoadError);
    {
        std::ofstream out(file.path(), std::ios::binary);
        out << R"({"rules":[]})" << std::string(1048577, ' ');
    }
    EXPECT_THROW(load_rule_file(file.path()), RuleLoadError);
    {
        std::ofstream out(file.path(), std::ios::binary | std::ios::trunc);
        out << Json{{"rules", Json::array({valid_rule()})}}.dump();
    }
    EXPECT_EQ(load_rule_file(file.path()).rules().size(), 1);
    auto invalid = valid_rule();
    invalid["sid"] = 2;
    invalid["content"] = "";
    EXPECT_THROW(load_rules(Json{{"rules", Json::array({valid_rule(), invalid})}}.dump()),
                 RuleLoadError);
}

}  // namespace
}  // namespace miniips
