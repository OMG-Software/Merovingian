// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/push/PushEvaluationContext.hpp"
#include "merovingian/push/PushRules.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <random>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

using merovingian::canonicaljson::Array;
using merovingian::canonicaljson::make_member;
using merovingian::canonicaljson::Object;
using merovingian::canonicaljson::Value;

[[nodiscard]] auto str_member(std::string key, std::string value) -> merovingian::canonicaljson::ObjectMember
{
    return make_member(std::move(key), Value{std::move(value)});
}

[[nodiscard]] auto make_event(std::string type, std::string sender, std::string room_id, Object content) -> Value
{
    auto obj = Object{};
    obj.push_back(str_member("type", std::move(type)));
    obj.push_back(str_member("sender", std::move(sender)));
    obj.push_back(str_member("room_id", std::move(room_id)));
    obj.push_back(make_member("content", Value{std::move(content)}));
    return Value{std::move(obj)};
}

[[nodiscard]] auto make_rule(std::string rule_id, bool enabled, Array conditions, Array actions) -> Value
{
    auto obj = Object{};
    obj.push_back(make_member("actions", Value{std::move(actions)}));
    obj.push_back(make_member("conditions", Value{std::move(conditions)}));
    obj.push_back(make_member("default", Value{true}));
    obj.push_back(make_member("enabled", Value{enabled}));
    obj.push_back(str_member("rule_id", std::move(rule_id)));
    return Value{std::move(obj)};
}

[[nodiscard]] auto make_content_rule(std::string rule_id, bool enabled, std::string pattern, Array actions) -> Value
{
    auto obj = Object{};
    obj.push_back(make_member("actions", Value{std::move(actions)}));
    obj.push_back(make_member("default", Value{true}));
    obj.push_back(make_member("enabled", Value{enabled}));
    obj.push_back(str_member("pattern", std::move(pattern)));
    obj.push_back(str_member("rule_id", std::move(rule_id)));
    return Value{std::move(obj)};
}

[[nodiscard]] auto cond_event_match(std::string key, std::string pattern) -> Value
{
    auto obj = Object{};
    obj.push_back(str_member("key", std::move(key)));
    obj.push_back(str_member("kind", "event_match"));
    obj.push_back(str_member("pattern", std::move(pattern)));
    return Value{std::move(obj)};
}

[[nodiscard]] auto cond_contains_display_name() -> Value
{
    auto obj = Object{};
    obj.push_back(str_member("kind", "contains_display_name"));
    return Value{std::move(obj)};
}

[[nodiscard]] auto cond_room_member_count(std::string is) -> Value
{
    auto obj = Object{};
    obj.push_back(str_member("is", std::move(is)));
    obj.push_back(str_member("kind", "room_member_count"));
    return Value{std::move(obj)};
}

[[nodiscard]] auto cond_sender_notification_permission(std::string key) -> Value
{
    auto obj = Object{};
    obj.push_back(str_member("key", std::move(key)));
    obj.push_back(str_member("kind", "sender_notification_permission"));
    return Value{std::move(obj)};
}

[[nodiscard]] auto cond_event_property_is(std::string key, Value value) -> Value
{
    auto obj = Object{};
    obj.push_back(str_member("key", std::move(key)));
    obj.push_back(str_member("kind", "event_property_is"));
    obj.push_back(make_member("value", std::move(value)));
    return Value{std::move(obj)};
}

[[nodiscard]] auto cond_event_property_contains(std::string key, Value value) -> Value
{
    auto obj = Object{};
    obj.push_back(str_member("key", std::move(key)));
    obj.push_back(str_member("kind", "event_property_contains"));
    obj.push_back(make_member("value", std::move(value)));
    return Value{std::move(obj)};
}

[[nodiscard]] auto action_notify() -> Value
{
    return Value{std::string{"notify"}};
}

[[nodiscard]] auto action_set_tweak_sound(std::string sound) -> Value
{
    auto obj = Object{};
    obj.push_back(str_member("set_tweak", "sound"));
    obj.push_back(str_member("value", std::move(sound)));
    return Value{std::move(obj)};
}

// "If a highlight tweak is given with no value, its value is defined to be
// true" — matches the shape `default_push_ruleset()` uses for the mention
// rules' highlight tweak.
[[nodiscard]] auto action_set_tweak_highlight() -> Value
{
    auto obj = Object{};
    obj.push_back(str_member("set_tweak", "highlight"));
    return Value{std::move(obj)};
}

// Builds a `content.m\.mentions` sub-object shaped as `default_push_ruleset()`
// expects: `{"user_ids": [...], "room": <bool>}`, nested under a single
// property literally named "m.mentions" (the dot in the name is why the
// condition `key` fields escape it as `m\.mentions`).
[[nodiscard]] auto mentions_content(Array user_ids, bool room_mention) -> Object
{
    auto mentions = Object{};
    mentions.push_back(make_member("user_ids", Value{std::move(user_ids)}));
    mentions.push_back(make_member("room", Value{room_mention}));
    auto content = Object{};
    content.push_back(make_member("m.mentions", Value{std::move(mentions)}));
    return content;
}

} // namespace

SCENARIO("Push rule kinds are evaluated in override > content > room > sender > underride precedence order", "[push]")
{
    GIVEN("a ruleset with one enabled, matching rule in every kind")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(make_member(
            "override", Value{Array{make_rule("override-wins", true, Array{cond_event_match("type", "m.room.message")},
                                              Array{action_notify()})}}));
        ruleset_object.push_back(make_member(
            "content", Value{Array{make_content_rule("content-wins", true, "hello", Array{action_notify()})}}));
        ruleset_object.push_back(
            make_member("room", Value{Array{make_rule("!room:example.org", true, {}, Array{action_notify()})}}));
        ruleset_object.push_back(
            make_member("sender", Value{Array{make_rule("@sender:example.org", true, {}, Array{action_notify()})}}));
        ruleset_object.push_back(
            make_member("underride",
                        Value{Array{make_rule("underride-wins", true, Array{cond_event_match("type", "m.room.message")},
                                              Array{action_notify()})}}));

        auto ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                      Object{str_member("body", "hello world"), str_member("msgtype", "m.text")});
        auto const context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};

        WHEN("every kind's rule matches the event")
        {
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the override rule wins")
            {
                REQUIRE(result.notify);
                REQUIRE(result.matched_rule_id == "override-wins");
            }
        }

        WHEN("the override rule is disabled")
        {
            ruleset.override_rules.front().enabled = false;
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the content rule wins")
            {
                REQUIRE(result.notify);
                REQUIRE(result.matched_rule_id == "content-wins");
            }
        }

        WHEN("the override and content rules are disabled")
        {
            ruleset.override_rules.front().enabled = false;
            ruleset.content_rules.front().enabled = false;
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the room rule wins")
            {
                REQUIRE(result.notify);
                REQUIRE(result.matched_rule_id == "!room:example.org");
            }
        }

        WHEN("the override, content, and room rules are disabled")
        {
            ruleset.override_rules.front().enabled = false;
            ruleset.content_rules.front().enabled = false;
            ruleset.room_rules.front().enabled = false;
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the sender rule wins")
            {
                REQUIRE(result.notify);
                REQUIRE(result.matched_rule_id == "@sender:example.org");
            }
        }

        WHEN("only the underride rule remains enabled")
        {
            ruleset.override_rules.front().enabled = false;
            ruleset.content_rules.front().enabled = false;
            ruleset.room_rules.front().enabled = false;
            ruleset.sender_rules.front().enabled = false;
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the underride rule wins")
            {
                REQUIRE(result.notify);
                REQUIRE(result.matched_rule_id == "underride-wins");
            }
        }
    }
}

SCENARIO("event_match condition matches a glob pattern against an event property", "[push]")
{
    GIVEN("an override rule with a single event_match condition on content.msgtype")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(make_member(
            "override",
            Value{Array{make_rule("notice-rule", true, Array{cond_event_match("content.msgtype", "m.notice")},
                                  Array{action_notify()})}}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto const context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};

        WHEN("the event's content.msgtype matches the pattern")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("msgtype", "m.notice")});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule matches and notifies")
            {
                REQUIRE(result.notify);
                REQUIRE(result.matched_rule_id == "notice-rule");
            }
        }

        WHEN("the event's content.msgtype does not match the pattern")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("msgtype", "m.text")});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("no rule matches and the outcome is dont_notify")
            {
                REQUIRE_FALSE(result.notify);
                REQUIRE(result.matched_rule_id.empty());
            }
        }
    }
}

SCENARIO("contains_display_name condition matches the receiving user's display name at a word boundary", "[push]")
{
    GIVEN("an override rule with a contains_display_name condition and a receiving user with a display name")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(
            make_member("override", Value{Array{make_rule("mention-rule", true, Array{cond_contains_display_name()},
                                                          Array{action_notify()})}}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};
        context.receiving_user_display_name = "Alice";

        WHEN("the message body contains the display name at a word boundary")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("body", "Hello Alice, how are you?")});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule matches")
            {
                REQUIRE(result.notify);
            }
        }

        WHEN("the display name appears only as part of a longer word")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("body", "Alicexyz said hello")});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule does not match")
            {
                REQUIRE_FALSE(result.notify);
            }
        }
    }
}

// PR #479 review finding P2: contains_display_name must compare the display
// name as literal text, never as a glob pattern. A display name is data
// supplied by an arbitrary user, not an author-written pattern — treating
// '*'/'?' in it as wildcards would let a user with display name "*" get
// highlighted on every single message in every room, regardless of whether
// it names them.
SCENARIO("contains_display_name treats the display name as literal text, never a glob pattern", "[push]")
{
    GIVEN("a receiving user whose display name is a bare '*' glob wildcard")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(
            make_member("override", Value{Array{make_rule("mention-rule", true, Array{cond_contains_display_name()},
                                                          Array{action_notify()})}}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};
        context.receiving_user_display_name = "*";

        WHEN("the message body contains no literal '*' character")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("body", "just an ordinary message, nothing special")});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule does not match -- '*' is not interpreted as a wildcard matching everything")
            {
                REQUIRE_FALSE(result.notify);
            }
        }

        WHEN("the message body does contain a literal '*' character at a word boundary")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("body", "look at this * right here")});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule matches the literal character")
            {
                REQUIRE(result.notify);
            }
        }
    }

    GIVEN("a receiving user whose display name contains a literal '?' character")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(
            make_member("override", Value{Array{make_rule("mention-rule", true, Array{cond_contains_display_name()},
                                                          Array{action_notify()})}}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};
        context.receiving_user_display_name = "Bob?";

        WHEN("the message body contains a different single character where '?' would glob-match")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("body", "hey Bobz nice to meet you")});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule does not match -- '?' is not interpreted as a single-character wildcard")
            {
                REQUIRE_FALSE(result.notify);
            }
        }

        WHEN("the message body contains the literal display name including the '?' character")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("body", "hey Bob? nice to meet you")});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule matches")
            {
                REQUIRE(result.notify);
            }
        }
    }

    GIVEN("a receiving user with an ordinary display name (regression: the fix must not break the normal case)")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(
            make_member("override", Value{Array{make_rule("mention-rule", true, Array{cond_contains_display_name()},
                                                          Array{action_notify()})}}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};
        context.receiving_user_display_name = "Alice";

        WHEN("the message body contains the display name at a word boundary")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("body", "Hello Alice, how are you?")});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule still matches")
            {
                REQUIRE(result.notify);
            }
        }
    }
}

SCENARIO("room_member_count condition matches numeric comparisons against the room's member count", "[push]")
{
    GIVEN("an override rule requiring exactly two room members")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(make_member(
            "override",
            Value{Array{make_rule("one-to-one", true, Array{cond_room_member_count("2")}, Array{action_notify()})}}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto const event =
            make_event("m.room.message", "@sender:example.org", "!room:example.org", Object{str_member("body", "hi")});

        WHEN("the room has exactly two members")
        {
            auto context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};
            context.room_member_count = 2U;
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule matches")
            {
                REQUIRE(result.notify);
            }
        }

        WHEN("the room has three members")
        {
            auto context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};
            context.room_member_count = 3U;
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule does not match")
            {
                REQUIRE_FALSE(result.notify);
            }
        }
    }
}

SCENARIO("sender_notification_permission condition matches when the sender's power level meets the threshold", "[push]")
{
    GIVEN("an override rule requiring the room notification power level")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(make_member(
            "override", Value{Array{make_rule("room-notif", true, Array{cond_sender_notification_permission("room")},
                                              Array{action_notify()})}}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                      Object{str_member("body", "@room please read")});

        WHEN("the sender's power level meets the required notification level")
        {
            auto context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};
            context.notification_power_levels["room"] = 50;
            context.sender_power_level = 50;
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule matches")
            {
                REQUIRE(result.notify);
            }
        }

        WHEN("the sender's power level is below the required notification level")
        {
            auto context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};
            context.notification_power_levels["room"] = 50;
            context.sender_power_level = 0;
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule does not match")
            {
                REQUIRE_FALSE(result.notify);
            }
        }
    }
}

SCENARIO(".m.rule.master, when enabled, suppresses notification regardless of other matching rules", "[push]")
{
    GIVEN("a ruleset with .m.rule.master enabled and another override rule that would otherwise notify")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(make_member(
            "override", Value{
                            Array{make_rule(".m.rule.master", true, {}, {}),
                                  make_rule("would-notify", true, Array{cond_event_match("type", "m.room.message")},
                                  Array{action_notify(), action_set_tweak_sound("default")})}
        }));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto const event =
            make_event("m.room.message", "@sender:example.org", "!room:example.org", Object{str_member("body", "hi")});
        auto const context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};

        WHEN("the event is evaluated")
        {
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the master rule wins and no notification is produced")
            {
                REQUIRE_FALSE(result.notify);
                REQUIRE(result.matched_rule_id == ".m.rule.master");
                REQUIRE_FALSE(result.tweak_sound.has_value());
            }
        }
    }

    GIVEN("the same ruleset with .m.rule.master disabled (the spec default)")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(make_member(
            "override", Value{
                            Array{make_rule(".m.rule.master", false, {}, {}),
                                  make_rule("would-notify", true, Array{cond_event_match("type", "m.room.message")},
                                  Array{action_notify(), action_set_tweak_sound("default")})}
        }));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto const event =
            make_event("m.room.message", "@sender:example.org", "!room:example.org", Object{str_member("body", "hi")});
        auto const context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};

        WHEN("the event is evaluated")
        {
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the next matching override rule wins and notifies with its tweak")
            {
                REQUIRE(result.notify);
                REQUIRE(result.matched_rule_id == "would-notify");
                REQUIRE(result.tweak_sound == std::optional<std::string>{"default"});
            }
        }
    }
}

SCENARIO("An event with no matching rule, or a matched rule with empty actions, produces a dont_notify outcome",
         "[push]")
{
    GIVEN("a ruleset with a rule that matches nothing in the event")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(make_member(
            "override", Value{Array{make_rule("suppress-notices", true,
                                              Array{cond_event_match("content.msgtype", "m.notice")}, {})}}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto const context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};

        WHEN("the event does not match any rule condition")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("msgtype", "m.text")});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the outcome is dont_notify with no matched rule")
            {
                REQUIRE_FALSE(result.notify);
                REQUIRE(result.matched_rule_id.empty());
            }
        }

        WHEN("the event matches a rule whose actions array is empty")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("msgtype", "m.notice")});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule is matched but produces dont_notify (empty actions carry no notify action)")
            {
                REQUIRE_FALSE(result.notify);
                REQUIRE(result.matched_rule_id == "suppress-notices");
            }
        }
    }

    GIVEN("an event sent by the receiving user themselves")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(
            make_member("override", Value{Array{make_rule("always-notify", true, {}, Array{action_notify()})}}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto const context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};

        WHEN("the event's sender is the receiving user")
        {
            auto const event = make_event("m.room.message", "@receiver:example.org", "!room:example.org",
                                          Object{str_member("body", "hi")});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the homeserver never notifies the user about their own events")
            {
                REQUIRE_FALSE(result.notify);
                REQUIRE(result.matched_rule_id.empty());
            }
        }
    }
}

SCENARIO("event_property_contains condition matches an array property containing an exact value", "[push]")
{
    GIVEN("an override rule matching the receiving user's ID inside content.m\\.mentions.user_ids")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(make_member(
            "override",
            Value{Array{make_rule("mention-rule", true,
                                  Array{cond_event_property_contains("content.m\\.mentions.user_ids",
                                                                     Value{std::string{"@receiver:example.org"}})},
                                  Array{action_notify()})}}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto const context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};

        WHEN("the array contains the receiving user's ID")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          mentions_content(Array{Value{std::string{"@receiver:example.org"}},
                                                                 Value{std::string{"@other:example.org"}}},
                                                           false));
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule matches and notifies")
            {
                REQUIRE(result.notify);
                REQUIRE(result.matched_rule_id == "mention-rule");
            }
        }

        WHEN("the array does not contain the receiving user's ID")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          mentions_content(Array{Value{std::string{"@other:example.org"}}}, false));
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule does not match")
            {
                REQUIRE_FALSE(result.notify);
            }
        }

        WHEN("the property is absent entirely")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("body", "no mentions here")});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule does not match (fails closed)")
            {
                REQUIRE_FALSE(result.notify);
            }
        }

        WHEN("the property at the key path is not an array")
        {
            auto mentions = Object{};
            mentions.push_back(str_member("user_ids", "@receiver:example.org"));
            auto content = Object{};
            content.push_back(make_member("m.mentions", Value{std::move(mentions)}));
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org", content);
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule does not match (a non-array target never contains anything)")
            {
                REQUIRE_FALSE(result.notify);
            }
        }
    }
}

SCENARIO("event_property_is condition matches an exact, type-strict value", "[push]")
{
    GIVEN("an override rule matching content.m\\.mentions.room == true (boolean)")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(make_member(
            "override", Value{Array{make_rule("room-mention-rule", true,
                                              Array{cond_event_property_is("content.m\\.mentions.room", Value{true})},
                                              Array{action_notify()})}}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto const context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};

        WHEN("the property is the boolean true")
        {
            auto const event =
                make_event("m.room.message", "@sender:example.org", "!room:example.org", mentions_content({}, true));
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule matches and notifies")
            {
                REQUIRE(result.notify);
                REQUIRE(result.matched_rule_id == "room-mention-rule");
            }
        }

        WHEN("the property is the string \"true\" instead of the boolean")
        {
            auto mentions = Object{};
            mentions.push_back(str_member("room", "true"));
            auto content = Object{};
            content.push_back(make_member("m.mentions", Value{std::move(mentions)}));
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org", content);
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule does not match (type strictness: a string is never equal to a boolean)")
            {
                REQUIRE_FALSE(result.notify);
            }
        }

        WHEN("the property is absent entirely")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("body", "no mentions here")});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule does not match (fails closed)")
            {
                REQUIRE_FALSE(result.notify);
            }
        }
    }
}

SCENARIO("Escaped dot-separated property paths resolve a literal dot or backslash within a path segment", "[push]")
{
    GIVEN("an event with a content property literally named \"m.relates_to\" (a literal dot in the property name)")
    {
        // The property name "m.relates_to" contains a literal dot, so per
        // docs/matrix-v1.19-spec/appendices.md#dot-separated-property-paths
        // the condition key must escape it as "m\.relates_to" — written here
        // as the C++ string literal "m\\.relates_to".
        auto relates_to = Object{};
        relates_to.push_back(str_member("rel_type", "m.replace"));
        auto content = Object{};
        content.push_back(make_member("m.relates_to", Value{std::move(relates_to)}));
        auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org", content);
        auto const context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};

        WHEN("event_property_is uses the escaped-dot key to reach the property")
        {
            auto ruleset_object = Object{};
            ruleset_object.push_back(make_member(
                "override", Value{Array{make_rule("escaped-dot-rule", true,
                                                  Array{cond_event_property_is("content.m\\.relates_to.rel_type",
                                                                               Value{std::string{"m.replace"}})},
                                                  Array{action_notify()})}}));
            auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the escaped dot is treated as part of the segment name, not a path separator, and the rule matches")
            {
                REQUIRE(result.notify);
                REQUIRE(result.matched_rule_id == "escaped-dot-rule");
            }
        }

        WHEN("event_match (the pre-existing condition kind) uses the same escaped-dot key")
        {
            auto ruleset_object = Object{};
            ruleset_object.push_back(make_member(
                "override",
                Value{Array{make_rule("escaped-dot-event-match", true,
                                      Array{cond_event_match("content.m\\.relates_to.rel_type", "m.replace")},
                                      Array{action_notify()})}}));
            auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("event_match resolves the same escaped path correctly, sharing the same path-splitting logic")
            {
                REQUIRE(result.notify);
                REQUIRE(result.matched_rule_id == "escaped-dot-event-match");
            }
        }
    }

    GIVEN("an event with a content property literally named \"m\\foo\" (a literal backslash in the property name)")
    {
        // The property name "m\foo" contains a literal backslash, so the
        // spec requires escaping it as "m\\foo" in the path. In C++ source,
        // the object's actual key is written "m\\foo" (one escaped
        // backslash -> runtime "m\foo"), and the lookup path is written
        // "content.m\\\\foo" (two escaped backslashes -> runtime
        // "content.m\\foo", i.e. an escaped literal backslash followed by
        // "foo").
        auto content = Object{};
        content.push_back(str_member("m\\foo", "bar"));
        auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org", content);
        auto const context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};

        auto ruleset_object = Object{};
        ruleset_object.push_back(make_member(
            "override",
            Value{Array{make_rule("escaped-backslash-rule", true,
                                  Array{cond_event_property_is("content.m\\\\foo", Value{std::string{"bar"}})},
                                  Array{action_notify()})}}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);

        WHEN("the event is evaluated")
        {
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the escaped backslash resolves to the literal property name and the rule matches")
            {
                REQUIRE(result.notify);
                REQUIRE(result.matched_rule_id == "escaped-backslash-rule");
            }
        }
    }
}

SCENARIO("Unresolvable property paths never match event_property_is or event_property_contains", "[push]")
{
    GIVEN("rules targeting a path that does not exist and a path that walks through a non-object")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(make_member(
            "override",
            Value{
                Array{make_rule("missing-path-is", true,
                      Array{cond_event_property_is("content.does.not.exist", Value{std::string{"x"}})},
                      Array{action_notify()}),
                      make_rule("through-scalar-contains", true,
                      Array{cond_event_property_contains("content.body.nested", Value{std::string{"x"}})},
                      Array{action_notify()})}
        }));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto const context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};

        WHEN("the event has neither the missing property nor an object at the intermediate segment")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("body", "just a plain string")});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("no rule matches and the outcome is dont_notify")
            {
                REQUIRE_FALSE(result.notify);
                REQUIRE(result.matched_rule_id.empty());
            }
        }
    }
}

SCENARIO("The default .m.rule.is_user_mention and .m.rule.is_room_mention rules notify on @-mentions", "[push]")
{
    GIVEN("override rules built in the exact shape default_push_ruleset() produces for the mention rules")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(make_member(
            "override",
            Value{
                Array{
                      make_rule(".m.rule.is_user_mention", true,
                      Array{cond_event_property_contains("content.m\\.mentions.user_ids",
                                                                 Value{std::string{"@receiver:example.org"}})},
                      Array{action_notify(), action_set_tweak_sound("default"), action_set_tweak_highlight()}),
                      make_rule(".m.rule.is_room_mention", true,
                      Array{cond_event_property_is("content.m\\.mentions.room", Value{true}),
                                    cond_sender_notification_permission("room")},
                      Array{action_notify(), action_set_tweak_highlight()}),
                      }
        }));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};
        context.notification_power_levels["room"] = 50;

        WHEN("the event's m.mentions.user_ids array contains the receiving user's ID")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          mentions_content(Array{Value{std::string{"@receiver:example.org"}}}, false));
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("is_user_mention matches and notifies with sound and highlight tweaks")
            {
                REQUIRE(result.notify);
                REQUIRE(result.matched_rule_id == ".m.rule.is_user_mention");
                REQUIRE(result.tweak_sound == std::optional<std::string>{"default"});
                REQUIRE(result.tweak_highlight);
            }
        }

        WHEN("the event's m.mentions.room is true and the sender has the required notification power level")
        {
            context.sender_power_level = 50;
            auto const event =
                make_event("m.room.message", "@sender:example.org", "!room:example.org", mentions_content({}, true));
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("is_room_mention matches and notifies with a highlight tweak")
            {
                REQUIRE(result.notify);
                REQUIRE(result.matched_rule_id == ".m.rule.is_room_mention");
                REQUIRE(result.tweak_highlight);
            }
        }

        WHEN("the event's m.mentions.room is true but the sender lacks the required notification power level")
        {
            context.sender_power_level = 0;
            auto const event =
                make_event("m.room.message", "@sender:example.org", "!room:example.org", mentions_content({}, true));
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("is_room_mention does not match")
            {
                REQUIRE_FALSE(result.notify);
            }
        }

        WHEN("the event carries no m.mentions property at all")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("body", "just a regular message")});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("neither mention rule matches and the outcome is dont_notify")
            {
                REQUIRE_FALSE(result.notify);
                REQUIRE(result.matched_rule_id.empty());
            }
        }
    }
}

namespace
{

// The matchers as they were before security audit run-1 (sp01.push-glob-dp-allocation-per-character),
// kept here as the reference the faster ones must agree with: a full O(n*m) dynamic-programming
// table per match, and for content.body every word-bounded substring tried in turn.
[[nodiscard]] auto reference_lower(std::string_view value) -> std::string
{
    auto out = std::string{value};
    std::ranges::transform(out, out.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return out;
}

[[nodiscard]] auto reference_glob_full(std::string_view value, std::string_view pattern) -> bool
{
    auto dp = std::vector<std::vector<bool>>(value.size() + 1U, std::vector<bool>(pattern.size() + 1U, false));
    dp[0U][0U] = true;
    for (auto j = std::size_t{0U}; j < pattern.size(); ++j)
    {
        if (pattern[j] == '*')
        {
            dp[0U][j + 1U] = dp[0U][j];
        }
    }
    for (auto i = std::size_t{0U}; i < value.size(); ++i)
    {
        for (auto j = std::size_t{0U}; j < pattern.size(); ++j)
        {
            if (pattern[j] == '*')
            {
                dp[i + 1U][j + 1U] = dp[i][j + 1U] || dp[i + 1U][j];
            }
            else if (pattern[j] == '?' || pattern[j] == value[i])
            {
                dp[i + 1U][j + 1U] = dp[i][j];
            }
        }
    }
    return dp[value.size()][pattern.size()];
}

[[nodiscard]] auto reference_is_word(char character) -> bool
{
    return (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
           (character >= '0' && character <= '9') || character == '_';
}

[[nodiscard]] auto reference_word_substring(std::string_view value, std::string_view pattern) -> bool
{
    auto const lowered = reference_lower(value);
    auto const lowered_pattern = reference_lower(pattern);
    for (auto start = std::size_t{0U}; start <= lowered.size(); ++start)
    {
        if (start != 0U && reference_is_word(lowered[start - 1U]))
        {
            continue;
        }
        for (auto end = start; end <= lowered.size(); ++end)
        {
            if (end != lowered.size() && reference_is_word(lowered[end]))
            {
                continue;
            }
            if (reference_glob_full(std::string_view{lowered}.substr(start, end - start), lowered_pattern))
            {
                return true;
            }
        }
    }
    return false;
}

[[nodiscard]] auto random_text(std::mt19937& rng, std::string_view alphabet, std::size_t max_length) -> std::string
{
    auto length = std::uniform_int_distribution<std::size_t>{0U, max_length}(rng);
    auto pick = std::uniform_int_distribution<std::size_t>{0U, alphabet.size() - 1U};
    auto out = std::string{};
    while (length-- > 0U)
    {
        out.push_back(alphabet[pick(rng)]);
    }
    return out;
}

} // namespace

// Security audit run-1 (sp01.push-glob-dp-allocation-per-character): push evaluation runs per
// local recipient, per stored event, while the runtime lock is held, on values the sender
// controls. The matchers must not allocate per character or try every substring pair, and must
// still give the spec's answer (appendices.md "Glob-style matching"; content.body matches any
// substring that starts and ends at a word boundary).
SCENARIO("Push glob matching agrees with the reference matcher without its per-character cost",
         "[push][security][sp01]")
{
    GIVEN("thousands of seeded random values and glob patterns over a small alphabet")
    {
        auto rng = std::mt19937{0x5eedU};
        auto const context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};

        WHEN("each is evaluated as a whole-value event_match and as a content.body match")
        {
            auto disagreements = std::vector<std::string>{};
            for (auto i = 0; i < 3000; ++i)
            {
                auto const value = random_text(rng, "abAB _-.*?", 14U);
                auto const pattern = random_text(rng, "abAB*?_ ", 6U);

                auto full_object = Object{};
                full_object.push_back(make_member(
                    "override", Value{Array{make_rule("full", true, Array{cond_event_match("content.msgtype", pattern)},
                                                      Array{action_notify()})}}));
                auto const full_ruleset = merovingian::push::parse_push_ruleset(full_object);
                auto const full_event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                                   Object{str_member("msgtype", value)});
                auto const full = merovingian::push::evaluate_push_rules(full_ruleset, full_event, context).notify;
                if (full != reference_glob_full(reference_lower(value), reference_lower(pattern)))
                {
                    disagreements.push_back("full: value='" + value + "' pattern='" + pattern + "'");
                }

                auto body_object = Object{};
                body_object.push_back(make_member(
                    "content", Value{Array{make_content_rule("body", true, pattern, Array{action_notify()})}}));
                auto const body_ruleset = merovingian::push::parse_push_ruleset(body_object);
                auto const body_event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                                   Object{str_member("body", value)});
                auto const body = merovingian::push::evaluate_push_rules(body_ruleset, body_event, context).notify;
                // A content rule with an empty pattern never matches (rule_matches_content guards
                // it before any glob matching), so the reference answer is false for it.
                if (body != (!pattern.empty() && reference_word_substring(value, pattern)))
                {
                    disagreements.push_back("body: value='" + value + "' pattern='" + pattern + "'");
                }
            }

            THEN("every answer matches the reference")
            {
                INFO(disagreements.size()
                     << " disagreements; first: " << (disagreements.empty() ? std::string{} : disagreements.front()));
                REQUIRE(disagreements.empty());
            }
        }
    }

    GIVEN("a 64 KiB message body made of thousands of one-letter words, and a content rule")
    {
        auto body = std::string{};
        while (body.size() < 64U * 1024U)
        {
            body += "a ";
        }
        auto ruleset_object = Object{};
        ruleset_object.push_back(
            make_member("content", Value{Array{make_content_rule("keyword", true, "x*y", Array{action_notify()})}}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto const event =
            make_event("m.room.message", "@sender:example.org", "!room:example.org", Object{str_member("body", body)});

        WHEN("it is evaluated")
        {
            auto const result = merovingian::push::evaluate_push_rules(
                ruleset, event, merovingian::push::PushEvaluationContext{"@receiver:example.org"});

            THEN("it finishes (one pass over the body, not every word pair) and does not match")
            {
                REQUIRE_FALSE(result.notify);
            }
        }
    }
}

// Regression for the linear whole-value matcher (security audit run-1, sp01): a value may itself
// contain '*'. The pattern's '*' is still a wildcard there; matching it literally against the
// value's '*' and then failing on the rest gave the wrong answer.
SCENARIO("A glob '*' stays a wildcard when the value itself contains '*'", "[push][security][sp01]")
{
    GIVEN("an override rule matching content.msgtype against the glob 'b*'")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(make_member(
            "override", Value{Array{make_rule("star", true, Array{cond_event_match("content.msgtype", "b*")},
                                              Array{action_notify()})}}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto const context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};

        WHEN("the event's msgtype is 'b*.*'")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("msgtype", "b*.*")});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule matches, as 'b' followed by anything")
            {
                REQUIRE(result.notify);
            }
        }
    }
}

// Security audit run-2 (F-39, ADR-0343): one recipient's evaluation of one event spends a bounded
// number of matcher steps on content.body across ALL rules, and searches a bounded prefix of the
// body. The spec states neither bound (it says a pattern matches "any substring ... which starts and
// ends at a word boundary"); the bound is the server's, so a match inside the prefix stays exact.
// Past the budget a glob does not match (fail closed) and the result says so.
SCENARIO("A recipient's content rules share one step budget per event", "[push][security][f39]")
{
    GIVEN("200 content rules with 512-byte non-matching patterns, and a 64 KiB message body")
    {
        auto pattern = std::string(511U, '*');
        pattern += 'z';
        auto rules = Array{};
        for (auto i = 0; i < 200; ++i)
        {
            rules.push_back(make_content_rule("r" + std::to_string(i), true, pattern, Array{action_notify()}));
        }
        auto ruleset_object = Object{};
        ruleset_object.push_back(make_member("content", Value{std::move(rules)}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto body = std::string{};
        while (body.size() < 64U * 1024U)
        {
            body += "a ";
        }
        auto const event =
            make_event("m.room.message", "@sender:example.org", "!room:example.org", Object{str_member("body", body)});

        WHEN("it is evaluated for one recipient")
        {
            auto const result = merovingian::push::evaluate_push_rules(
                ruleset, event, merovingian::push::PushEvaluationContext{"@receiver:example.org"});

            THEN("the matcher spent no more than the budget, said it ran out, and no rule matched")
            {
                REQUIRE(result.glob_steps_used <= merovingian::push::max_push_glob_steps_per_evaluation);
                REQUIRE(result.glob_budget_exhausted);
                REQUIRE_FALSE(result.notify);
            }
        }
    }

    GIVEN("a content rule for 'needle' and an ordinary short message that contains it")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(
            make_member("content", Value{Array{make_content_rule("keyword", true, "needle", Array{action_notify()})}}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                      Object{str_member("body", "please find the needle in this haystack")});

        WHEN("it is evaluated")
        {
            auto const result = merovingian::push::evaluate_push_rules(
                ruleset, event, merovingian::push::PushEvaluationContext{"@receiver:example.org"});

            THEN("the rule matches and the budget is barely touched")
            {
                REQUIRE(result.notify);
                REQUIRE(result.matched_rule_id == "keyword");
                REQUIRE_FALSE(result.glob_budget_exhausted);
                REQUIRE(result.glob_steps_used < merovingian::push::max_push_glob_steps_per_evaluation / 100U);
            }
        }
    }
}

SCENARIO("Only the first part of a long content.body is searched for a keyword", "[push][security][f39]")
{
    GIVEN("a content rule for 'needle'")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(
            make_member("content", Value{Array{make_content_rule("keyword", true, "needle", Array{action_notify()})}}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto const context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};
        auto const padding = std::string(merovingian::push::max_push_glob_body_bytes * 2U, 'x');

        WHEN("the keyword is near the start of a body twice the cap")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("body", "a needle " + padding)});

            THEN("it still matches")
            {
                REQUIRE(merovingian::push::evaluate_push_rules(ruleset, event, context).notify);
            }
        }

        WHEN("the keyword follows the cap")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("body", padding + " needle")});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("it does not match, and the evaluation stays within the budget")
            {
                REQUIRE_FALSE(result.notify);
                REQUIRE(result.glob_steps_used <= merovingian::push::max_push_glob_steps_per_evaluation);
            }
        }

        WHEN("the keyword ends exactly at the cap but its word carries on past it")
        {
            auto body = std::string(merovingian::push::max_push_glob_body_bytes - 6U, ' ');
            body += "needles and more";
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("body", body)});

            THEN("the cut is not taken for a word boundary, so it does not match")
            {
                REQUIRE_FALSE(merovingian::push::evaluate_push_rules(ruleset, event, context).notify);
            }
        }

        WHEN("the keyword ends exactly at the cap and a space follows")
        {
            auto body = std::string(merovingian::push::max_push_glob_body_bytes - 6U, ' ');
            body += "needle and more";
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("body", body)});

            THEN("it matches at the real boundary")
            {
                REQUIRE(merovingian::push::evaluate_push_rules(ruleset, event, context).notify);
            }
        }
    }
}

// Security audit run-2 release gate (ADR-0607): an event_match on a key other than content.body, and
// the array scan of event_property_contains, draw from the same per-evaluation step budget as the
// body globs, and a whole-value glob refuses a value longer than max_push_glob_key_value_bytes.
SCENARIO("A glob on a key other than content.body shares the evaluation's step budget", "[push][security][gate-h]")
{
    GIVEN("200 override rules, each an event_match on content.x with a 510-byte worst-case pattern")
    {
        auto pattern = std::string{"*"};
        pattern += std::string(508U, 'a');
        pattern += 'b';
        auto rules = Array{};
        for (auto i = 0; i < 200; ++i)
        {
            rules.push_back(make_rule("r" + std::to_string(i), true, Array{cond_event_match("content.x", pattern)},
                                      Array{action_notify()}));
        }
        auto ruleset_object = Object{};
        ruleset_object.push_back(make_member("override", Value{std::move(rules)}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto const context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};

        WHEN("an event carries a value of the largest length the matcher accepts")
        {
            auto const event =
                make_event("m.room.message", "@sender:example.org", "!room:example.org",
                           Object{str_member("x", std::string(merovingian::push::max_push_glob_key_value_bytes, 'a'))});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the matcher spent no more than the budget, said it ran out, and nothing matched")
            {
                REQUIRE(result.glob_steps_used <= merovingian::push::max_push_glob_steps_per_evaluation);
                REQUIRE(result.glob_budget_exhausted);
                REQUIRE_FALSE(result.notify);
            }
        }

        WHEN("an event carries a 60000-byte value")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("x", std::string(60000U, 'a'))});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the value is refused outright, without spending the budget")
            {
                REQUIRE_FALSE(result.notify);
                REQUIRE(result.glob_steps_used < merovingian::push::max_push_glob_steps_per_evaluation / 100U);
            }
        }
    }

    GIVEN("an override rule that matches content.msgtype against 'M.*'")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(make_member(
            "override", Value{Array{make_rule("text", true, Array{cond_event_match("content.msgtype", "M.*")},
                                              Array{action_notify()})}}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto const context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};

        WHEN("an ordinary event is evaluated")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{str_member("msgtype", "m.text")});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the rule still matches, case-insensitively, for a small number of steps")
            {
                REQUIRE(result.notify);
                REQUIRE_FALSE(result.glob_budget_exhausted);
                REQUIRE(result.glob_steps_used < 100U);
            }
        }

        WHEN("the value is exactly the cap, and then one byte over it")
        {
            auto at_cap = std::string{"m."};
            at_cap.append(merovingian::push::max_push_glob_key_value_bytes - 2U, 'x');
            auto const at_cap_event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                                 Object{str_member("msgtype", at_cap)});
            auto const over_event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                               Object{str_member("msgtype", at_cap + "x")});

            THEN("the one at the cap matches and the one over it does not")
            {
                REQUIRE(merovingian::push::evaluate_push_rules(ruleset, at_cap_event, context).notify);
                REQUIRE_FALSE(merovingian::push::evaluate_push_rules(ruleset, over_event, context).notify);
            }
        }
    }

    GIVEN("a pattern with no wildcard")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(
            make_member("override", Value{Array{make_rule("exact", true, Array{cond_event_match("content.x", "abc")},
                                                          Array{action_notify()})}}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto const context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};

        WHEN("the value is 60000 bytes long, and then equal to the pattern in another case")
        {
            auto const long_event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                               Object{str_member("x", std::string(60000U, 'a'))});
            auto const equal_event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                                Object{str_member("x", "ABC")});

            THEN("only the equal one matches")
            {
                REQUIRE_FALSE(merovingian::push::evaluate_push_rules(ruleset, long_event, context).notify);
                REQUIRE(merovingian::push::evaluate_push_rules(ruleset, equal_event, context).notify);
            }
        }
    }
}

SCENARIO("An event_property_contains scan of a large array is charged to the step budget", "[push][security][gate-h]")
{
    GIVEN("200 override rules that each look for a string in content.list, and an array of 20000 other strings")
    {
        auto rules = Array{};
        for (auto i = 0; i < 200; ++i)
        {
            rules.push_back(make_rule("r" + std::to_string(i), true,
                                      Array{cond_event_property_contains("content.list", Value{std::string{"needle"}})},
                                      Array{action_notify()}));
        }
        auto ruleset_object = Object{};
        ruleset_object.push_back(make_member("override", Value{std::move(rules)}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);
        auto const context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};
        auto list = Array{};
        for (auto i = 0; i < 20000; ++i)
        {
            list.push_back(Value{std::string{"x"}});
        }

        WHEN("an event carries the array")
        {
            auto const event = make_event("m.room.message", "@sender:example.org", "!room:example.org",
                                          Object{make_member("list", Value{std::move(list)})});
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the scans stop at the budget and the evaluation says so")
            {
                REQUIRE(result.glob_steps_used <= merovingian::push::max_push_glob_steps_per_evaluation);
                REQUIRE(result.glob_budget_exhausted);
                REQUIRE_FALSE(result.notify);
            }
        }
    }

    GIVEN("a rule that looks for a string in a short array")
    {
        auto ruleset_object = Object{};
        ruleset_object.push_back(make_member(
            "override",
            Value{Array{make_rule("find", true,
                                  Array{cond_event_property_contains("content.list", Value{std::string{"needle"}})},
                                  Array{action_notify()})}}));
        auto const ruleset = merovingian::push::parse_push_ruleset(ruleset_object);

        WHEN("the array holds it")
        {
            auto const event = make_event(
                "m.room.message", "@sender:example.org", "!room:example.org",
                Object{
                    make_member("list", Value{Array{Value{std::string{"a"}}, Value{std::string{"needle"}}}}
                     )
            });

            THEN("it matches")
            {
                REQUIRE(merovingian::push::evaluate_push_rules(
                            ruleset, event, merovingian::push::PushEvaluationContext{"@receiver:example.org"})
                            .notify);
            }
        }
    }
}
