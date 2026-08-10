// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/push/push_rules.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <utility>

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
