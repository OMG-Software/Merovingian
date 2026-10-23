// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// push::UserPushRules: a user's push rules over the server defaults (R19, ADR-0204).
// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#push-rules-api

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/homeserver/default_push_ruleset.hpp"
#include "merovingian/push/user_push_rules.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using merovingian::canonicaljson::Array;
using merovingian::canonicaljson::Object;
using merovingian::canonicaljson::Value;
using merovingian::push::PushRuleEditOutcome;
using merovingian::push::PushRuleKind;
using merovingian::push::PushRulePlacement;
using merovingian::push::UserPushRules;

constexpr auto alice = std::string_view{"@alice:example.org"};

[[nodiscard]] auto json(std::string_view text) -> Value
{
    auto parsed = merovingian::canonicaljson::parse_lossless(text);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return std::move(parsed.value);
}

[[nodiscard]] auto rules_for(Object const& stored = {}, std::size_t max_rules = 200U) -> UserPushRules
{
    return UserPushRules{merovingian::homeserver::default_push_ruleset(alice), stored, max_rules};
}

[[nodiscard]] auto member_of(Object const& object, std::string_view key) -> Value const*
{
    for (auto const& member : object)
    {
        if (member.key == key)
        {
            return member.value.get();
        }
    }
    return nullptr;
}

// The rule IDs of one kind in the served order.
[[nodiscard]] auto rule_ids(UserPushRules const& rules, std::string_view kind) -> std::vector<std::string>
{
    auto ids = std::vector<std::string>{};
    auto const ruleset = rules.ruleset();
    auto const* array_value = member_of(ruleset, kind);
    REQUIRE(array_value != nullptr);
    for (auto const& rule : std::get<Array>(array_value->storage()))
    {
        ids.push_back(std::get<std::string>(member_of(std::get<Object>(rule.storage()), "rule_id")->storage()));
    }
    return ids;
}

[[nodiscard]] auto flag_of(Object const& rule, std::string_view key) -> bool
{
    return std::get<bool>(member_of(rule, key)->storage());
}

auto const notify_body = std::string_view{R"({"actions":["notify"],"pattern":"cake"})"};

} // namespace

SCENARIO("A user with no stored push rules has the server-default ruleset", "[push][push_rules_api][r19]")
{
    GIVEN("no stored rules")
    {
        WHEN("the user's rules are built")
        {
            auto const rules = rules_for();

            THEN("every kind is served, .m.rule.master leads override, and no user rule exists")
            {
                REQUIRE(rules.user_rule_count() == 0U);
                REQUIRE(rule_ids(rules, "override").front() == ".m.rule.master");
                REQUIRE(rule_ids(rules, "room").empty());
                REQUIRE(rule_ids(rules, "sender").empty());
                REQUIRE_FALSE(rule_ids(rules, "underride").empty());
            }
        }
    }
}

SCENARIO("PUT creates an enabled user rule as the most important of its kind", "[push][push_rules_api][r19]")
{
    GIVEN("a user with a content rule already")
    {
        auto rules = rules_for();
        REQUIRE(rules.put_rule(PushRuleKind::content, "first", json(notify_body), {}) == PushRuleEditOutcome::applied);

        WHEN("a second content rule is created without before or after")
        {
            auto const result = rules.put_rule(PushRuleKind::content, "second", json(notify_body), {});

            THEN("it is enabled, not default, and ranks first")
            {
                REQUIRE(result == PushRuleEditOutcome::applied);
                REQUIRE(rule_ids(rules, "content") == std::vector<std::string>{"second", "first"});
                auto const rule = rules.rule(PushRuleKind::content, "second");
                REQUIRE(rule.has_value());
                REQUIRE(flag_of(*rule, "enabled"));
                REQUIRE_FALSE(flag_of(*rule, "default"));
            }
        }

        WHEN("an override rule is created")
        {
            REQUIRE(rules.put_rule(PushRuleKind::override_kind, "mine", json(R"({"actions":[]})"), {}) ==
                    PushRuleEditOutcome::applied);

            THEN("it follows .m.rule.master and precedes the other server-default overrides")
            {
                auto const ids = rule_ids(rules, "override");
                REQUIRE(ids.at(0U) == ".m.rule.master");
                REQUIRE(ids.at(1U) == "mine");
                REQUIRE(ids.at(2U) == ".m.rule.suppress_notices");
            }
        }
    }
}

SCENARIO("PUT honours before and after relative to user rules only", "[push][push_rules_api][r19]")
{
    GIVEN("content rules a then b")
    {
        auto rules = rules_for();
        REQUIRE(rules.put_rule(PushRuleKind::content, "b", json(notify_body), {}) == PushRuleEditOutcome::applied);
        REQUIRE(rules.put_rule(PushRuleKind::content, "a", json(notify_body), {}) == PushRuleEditOutcome::applied);

        WHEN("c is put after a")
        {
            REQUIRE(rules.put_rule(PushRuleKind::content, "c", json(notify_body), {std::nullopt, "a"}) ==
                    PushRuleEditOutcome::applied);

            THEN("c is next-less important than a")
            {
                REQUIRE(rule_ids(rules, "content") == std::vector<std::string>{"a", "c", "b"});
            }
        }

        WHEN("c is put with both before b and after a")
        {
            REQUIRE(rules.put_rule(PushRuleKind::content, "c", json(notify_body), {"b", "a"}) ==
                    PushRuleEditOutcome::applied);

            THEN("before decides")
            {
                REQUIRE(rule_ids(rules, "content") == std::vector<std::string>{"a", "c", "b"});
            }
        }

        WHEN("existing rule b is put before a")
        {
            REQUIRE(rules.put_rule(PushRuleKind::content, "b", json(notify_body), {"a", std::nullopt}) ==
                    PushRuleEditOutcome::applied);

            THEN("b moves")
            {
                REQUIRE(rule_ids(rules, "content") == std::vector<std::string>{"b", "a"});
            }
        }

        WHEN("a rule is placed relative to a rule that does not exist")
        {
            auto const result = rules.put_rule(PushRuleKind::content, "c", json(notify_body), {"zzz", std::nullopt});

            THEN("it is refused and nothing changes")
            {
                REQUIRE(result == PushRuleEditOutcome::unknown_relative_rule);
                REQUIRE(rule_ids(rules, "content") == std::vector<std::string>{"a", "b"});
            }
        }

        WHEN("a rule is placed relative to a server-default rule")
        {
            auto const result = rules.put_rule(PushRuleKind::override_kind, "x", json(R"({"actions":[]})"),
                                               {".m.rule.suppress_notices", std::nullopt});

            THEN("it is refused: \"It is not possible to add a rule relative to a predefined server rule\"")
            {
                REQUIRE(result == PushRuleEditOutcome::relative_to_server_default);
            }
        }
    }
}

SCENARIO("PUT updates an existing rule in place and keeps its enabled state", "[push][push_rules_api][r19]")
{
    GIVEN("a disabled user rule")
    {
        auto rules = rules_for();
        REQUIRE(rules.put_rule(PushRuleKind::content, "a", json(notify_body), {}) == PushRuleEditOutcome::applied);
        REQUIRE(rules.put_rule(PushRuleKind::content, "b", json(notify_body), {}) == PushRuleEditOutcome::applied);
        REQUIRE(rules.set_enabled(PushRuleKind::content, "a", false) == PushRuleEditOutcome::applied);

        WHEN("it is put again with a new pattern")
        {
            REQUIRE(rules.put_rule(PushRuleKind::content, "a", json(R"({"actions":[],"pattern":"tea"})"), {}) ==
                    PushRuleEditOutcome::applied);

            THEN("its parameters change, its place and enabled state do not")
            {
                REQUIRE(rule_ids(rules, "content") == std::vector<std::string>{"b", "a"});
                auto const rule = rules.rule(PushRuleKind::content, "a");
                REQUIRE(rule.has_value());
                REQUIRE_FALSE(flag_of(*rule, "enabled"));
                REQUIRE(std::get<std::string>(member_of(*rule, "pattern")->storage()) == "tea");
            }
        }
    }
}

SCENARIO("PUT refuses rule IDs and bodies the spec does not allow", "[push][push_rules_api][r19][security]")
{
    GIVEN("a user's rules")
    {
        auto rules = rules_for();

        WHEN("rule IDs starting with a dot, or containing a slash or backslash, are put")
        {
            THEN("the dot is reserved for server-default rules and the others are invalid")
            {
                REQUIRE(rules.put_rule(PushRuleKind::content, ".mine", json(notify_body), {}) ==
                        PushRuleEditOutcome::server_default_rule);
                REQUIRE(rules.put_rule(PushRuleKind::content, "a/b", json(notify_body), {}) ==
                        PushRuleEditOutcome::invalid_rule_id);
                REQUIRE(rules.put_rule(PushRuleKind::content, "a\\b", json(notify_body), {}) ==
                        PushRuleEditOutcome::invalid_rule_id);
            }
        }

        WHEN("room and sender rules are named by something that is not a room or user ID")
        {
            THEN("they are refused")
            {
                REQUIRE(rules.put_rule(PushRuleKind::room, "@bob:example.org", json(R"({"actions":[]})"), {}) ==
                        PushRuleEditOutcome::invalid_rule_id);
                REQUIRE(rules.put_rule(PushRuleKind::sender, "!room:example.org", json(R"({"actions":[]})"), {}) ==
                        PushRuleEditOutcome::invalid_rule_id);
                REQUIRE(rules.put_rule(PushRuleKind::room, "!room:example.org", json(R"({"actions":[]})"), {}) ==
                        PushRuleEditOutcome::applied);
            }
        }

        WHEN("bodies lack actions, a content rule lacks its pattern, or an action is unknown")
        {
            THEN("each is refused as an invalid rule")
            {
                REQUIRE(rules.put_rule(PushRuleKind::content, "a", json(R"({"pattern":"x"})"), {}) ==
                        PushRuleEditOutcome::invalid_rule);
                REQUIRE(rules.put_rule(PushRuleKind::content, "a", json(R"({"actions":[]})"), {}) ==
                        PushRuleEditOutcome::invalid_rule);
                REQUIRE(rules.put_rule(PushRuleKind::override_kind, "a", json(R"({"actions":["explode"]})"), {}) ==
                        PushRuleEditOutcome::invalid_rule);
                REQUIRE(rules.put_rule(PushRuleKind::override_kind, "a",
                                       json(R"({"actions":[{"set_tweak":"highlight","value":"yes"}]})"),
                                       {}) == PushRuleEditOutcome::invalid_rule);
                REQUIRE(rules.put_rule(PushRuleKind::override_kind, "a",
                                       json(R"({"actions":[],"conditions":[{"kind":"event_match","key":"type"}]})"),
                                       {}) == PushRuleEditOutcome::invalid_rule);
                REQUIRE(rules.user_rule_count() == 0U);
            }
        }

        WHEN("a pattern or the conditions exceed their bounds")
        {
            auto const long_pattern = std::string(merovingian::push::max_push_rule_pattern_bytes + 1U, 'x');
            auto conditions = std::string{"["};
            for (auto i = std::size_t{0U}; i <= merovingian::push::max_push_rule_conditions; ++i)
            {
                conditions += std::string{i == 0U ? "" : ","} + R"({"kind":"contains_display_name"})";
            }
            conditions += "]";

            THEN("the rule is refused before it can be stored")
            {
                REQUIRE(rules.put_rule(PushRuleKind::content, "a",
                                       json(R"({"actions":[],"pattern":")" + long_pattern + "\"}"),
                                       {}) == PushRuleEditOutcome::invalid_rule);
                REQUIRE(rules.put_rule(PushRuleKind::override_kind, "a",
                                       json(R"({"actions":[],"conditions":)" + conditions + "}"),
                                       {}) == PushRuleEditOutcome::invalid_rule);
            }
        }
    }
}

SCENARIO("Historical actions are stripped from stored rules", "[push][push_rules_api][r19]")
{
    GIVEN("a rule put with dont_notify and coalesce")
    {
        auto rules = rules_for();
        REQUIRE(rules.put_rule(PushRuleKind::override_kind, "a",
                               json(R"({"actions":["dont_notify","coalesce","notify"],"conditions":[]})"),
                               {}) == PushRuleEditOutcome::applied);

        WHEN("the rule is read back")
        {
            auto const rule = rules.rule(PushRuleKind::override_kind, "a");

            THEN("only notify remains (\"by stripping them from actions arrays\")")
            {
                REQUIRE(rule.has_value());
                auto const& actions = std::get<Array>(member_of(*rule, "actions")->storage());
                REQUIRE(actions.size() == 1U);
                REQUIRE(std::get<std::string>(actions.front().storage()) == "notify");
            }
        }
    }
}

SCENARIO("A user's rule count is capped", "[push][push_rules_api][r19][security]")
{
    GIVEN("a user at a cap of two rules")
    {
        auto rules = rules_for({}, 2U);
        REQUIRE(rules.put_rule(PushRuleKind::content, "a", json(notify_body), {}) == PushRuleEditOutcome::applied);
        REQUIRE(rules.put_rule(PushRuleKind::room, "!r:example.org", json(R"({"actions":[]})"), {}) ==
                PushRuleEditOutcome::applied);

        WHEN("a third rule is created")
        {
            auto const result = rules.put_rule(PushRuleKind::content, "c", json(notify_body), {});

            THEN("it is refused, while updating an existing rule still succeeds")
            {
                REQUIRE(result == PushRuleEditOutcome::too_many_rules);
                REQUIRE(rules.put_rule(PushRuleKind::content, "a", json(notify_body), {}) ==
                        PushRuleEditOutcome::applied);
                REQUIRE(rules.user_rule_count() == 2U);
            }
        }
    }
}

SCENARIO("Server-default rules can be enabled and given actions but not deleted", "[push][push_rules_api][r19]")
{
    GIVEN("the default ruleset")
    {
        auto rules = rules_for();

        WHEN(".m.rule.master is enabled and .m.rule.message given new actions")
        {
            REQUIRE(rules.set_enabled(PushRuleKind::override_kind, ".m.rule.master", true) ==
                    PushRuleEditOutcome::applied);
            REQUIRE(rules.set_actions(PushRuleKind::underride, ".m.rule.message", json(R"([])")) ==
                    PushRuleEditOutcome::applied);

            THEN("the defaults reflect both changes and remain default rules")
            {
                auto const master = rules.rule(PushRuleKind::override_kind, ".m.rule.master");
                REQUIRE(flag_of(*master, "enabled"));
                REQUIRE(flag_of(*master, "default"));
                auto const message = rules.rule(PushRuleKind::underride, ".m.rule.message");
                REQUIRE(std::get<Array>(member_of(*message, "actions")->storage()).empty());
            }
        }

        WHEN("a default rule is deleted, and an unknown rule is deleted or enabled")
        {
            THEN("the default is refused and the unknown rule is not found")
            {
                REQUIRE(rules.delete_rule(PushRuleKind::override_kind, ".m.rule.master") ==
                        PushRuleEditOutcome::server_default_rule);
                REQUIRE(rules.delete_rule(PushRuleKind::content, "nope") == PushRuleEditOutcome::not_found);
                REQUIRE(rules.set_enabled(PushRuleKind::content, "nope", true) == PushRuleEditOutcome::not_found);
                REQUIRE(rules.set_actions(PushRuleKind::override_kind, ".m.rule.master", json(R"(["boom"])")) ==
                        PushRuleEditOutcome::invalid_rule);
            }
        }
    }
}

SCENARIO("A stored ruleset round-trips over the current server defaults", "[push][push_rules_api][r19]")
{
    GIVEN("rules edited, served, and read back as stored account data")
    {
        auto edited = rules_for();
        REQUIRE(edited.put_rule(PushRuleKind::content, "a", json(notify_body), {}) == PushRuleEditOutcome::applied);
        REQUIRE(edited.put_rule(PushRuleKind::content, "b", json(notify_body), {}) == PushRuleEditOutcome::applied);
        REQUIRE(edited.set_enabled(PushRuleKind::content, "a", false) == PushRuleEditOutcome::applied);
        REQUIRE(edited.set_enabled(PushRuleKind::override_kind, ".m.rule.suppress_notices", false) ==
                PushRuleEditOutcome::applied);

        WHEN("the stored copy also names a default the server no longer has and an invalid user rule")
        {
            auto stored = edited.ruleset();
            auto stale = json(R"({"content":[{"rule_id":".m.rule.gone","default":true,"enabled":true,
                "actions":[],"pattern":"x"},{"rule_id":"no/slash","actions":[],"pattern":"x"}]})");
            for (auto& member : stored)
            {
                if (member.key == "content")
                {
                    auto array = std::get<Array>(member.value->storage());
                    for (auto const& extra :
                         std::get<Array>(member_of(std::get<Object>(stale.storage()), "content")->storage()))
                    {
                        array.push_back(extra);
                    }
                    member.value = std::make_unique<Value>(std::move(array));
                }
            }
            auto const reread = rules_for(stored);

            THEN("user rules, their order and enabled state, and default changes survive; the rest is dropped")
            {
                REQUIRE(rule_ids(reread, "content") == std::vector<std::string>{"b", "a"});
                REQUIRE_FALSE(flag_of(*reread.rule(PushRuleKind::content, "a"), "enabled"));
                REQUIRE_FALSE(
                    flag_of(*reread.rule(PushRuleKind::override_kind, ".m.rule.suppress_notices"), "enabled"));
                REQUIRE(rule_ids(reread, "override").front() == ".m.rule.master");
                REQUIRE(reread.user_rule_count() == 2U);
            }
        }

        WHEN("it is read back under a lower cap")
        {
            auto const reread = rules_for(edited.ruleset(), 1U);

            THEN("only the most important stored rules up to the cap are kept")
            {
                REQUIRE(rule_ids(reread, "content") == std::vector<std::string>{"b"});
            }
        }
    }
}
