// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |          DEFAULT PUSH RULESET — LEGACY BODY-SCANNING DEFAULTS           |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19 §push-notifications,             |
// |  "Predefined Rules": "[Changed in v1.17]: the legacy default push      |
// |  rules that looked for mentions in the body of the event were         |
// |  removed."                                                             |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#push-notifications |
// |                                                                         |
// |  PR #479 review finding P2 (`.m.rule.roomnotif`) plus the equally      |
// |  stale `.m.rule.contains_display_name` default this audit also found:  |
// |  neither rule_id appears in the current spec's ten-entry "Default      |
// |  Override Rules" list, and both are exactly the body-text-scanning     |
// |  pattern that list's v1.17 change removed. Drives default_push_        |
// |  ruleset() and evaluate_push_rules() directly -- no HTTP layer, no     |
// |  database -- to prove both the ruleset shape and the resulting         |
// |  evaluation behaviour.                                                 |
// +-------------------------------------------------------------------------+

#include "merovingian/homeserver/default_push_ruleset.hpp"
#include "merovingian/push/push_rules.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>

namespace
{

[[nodiscard]] auto push_rule_by_id(merovingian::canonicaljson::Array const& rules, std::string_view rule_id)
    -> merovingian::canonicaljson::Object const*
{
    for (auto const& entry : rules)
    {
        auto const* object = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
        if (object == nullptr)
        {
            continue;
        }
        auto const it = std::ranges::find_if(*object, [](merovingian::canonicaljson::ObjectMember const& member) {
            return member.key == "rule_id";
        });
        if (it == object->end())
        {
            continue;
        }
        auto const* id_string = std::get_if<std::string>(&it->value->storage());
        if (id_string != nullptr && *id_string == rule_id)
        {
            return object;
        }
    }
    return nullptr;
}

[[nodiscard]] auto make_event_with_body(std::string sender, std::string room_id, std::string body)
    -> merovingian::canonicaljson::Value
{
    using merovingian::canonicaljson::make_member;
    using merovingian::canonicaljson::Object;
    using merovingian::canonicaljson::Value;

    auto content = Object{};
    content.push_back(make_member("body", Value{std::move(body)}));
    content.push_back(make_member("msgtype", Value{std::string{"m.text"}}));

    auto event = Object{};
    event.push_back(make_member("type", Value{std::string{"m.room.message"}}));
    event.push_back(make_member("sender", Value{std::move(sender)}));
    event.push_back(make_member("room_id", Value{std::move(room_id)}));
    event.push_back(make_member("content", Value{std::move(content)}));
    return Value{std::move(event)};
}

} // namespace

SCENARIO("The default override ruleset does not contain the legacy body-scanning mention rules", "[push]")
{
    GIVEN("the server's default push ruleset for a user")
    {
        auto const ruleset = merovingian::homeserver::default_push_ruleset("@receiver:example.org");
        auto const override_it =
            std::ranges::find_if(ruleset, [](merovingian::canonicaljson::ObjectMember const& member) {
                return member.key == "override";
            });
        REQUIRE(override_it != ruleset.end());
        auto const* override_rules = std::get_if<merovingian::canonicaljson::Array>(&override_it->value->storage());
        REQUIRE(override_rules != nullptr);

        THEN("the ten spec-defined default override rules are present")
        {
            REQUIRE(push_rule_by_id(*override_rules, ".m.rule.master") != nullptr);
            REQUIRE(push_rule_by_id(*override_rules, ".m.rule.suppress_notices") != nullptr);
            REQUIRE(push_rule_by_id(*override_rules, ".m.rule.invite_for_me") != nullptr);
            REQUIRE(push_rule_by_id(*override_rules, ".m.rule.member_event") != nullptr);
            REQUIRE(push_rule_by_id(*override_rules, ".m.rule.is_user_mention") != nullptr);
            REQUIRE(push_rule_by_id(*override_rules, ".m.rule.is_room_mention") != nullptr);
            REQUIRE(push_rule_by_id(*override_rules, ".m.rule.tombstone") != nullptr);
            REQUIRE(push_rule_by_id(*override_rules, ".m.rule.reaction") != nullptr);
            REQUIRE(push_rule_by_id(*override_rules, ".m.rule.room.server_acl") != nullptr);
            REQUIRE(push_rule_by_id(*override_rules, ".m.rule.suppress_edits") != nullptr);
        }

        THEN("neither legacy body-scanning default rule is present")
        {
            REQUIRE(push_rule_by_id(*override_rules, ".m.rule.roomnotif") == nullptr);
            REQUIRE(push_rule_by_id(*override_rules, ".m.rule.contains_display_name") == nullptr);
        }
    }
}

SCENARIO("A message body containing literal \"@room\" text alone no longer produces a highlighted notification",
         "[push]")
{
    GIVEN("the real default ruleset, parsed and evaluated exactly as room_service.cpp does for delivery")
    {
        auto const raw_ruleset = merovingian::homeserver::default_push_ruleset("@receiver:example.org");
        auto const ruleset = merovingian::push::parse_push_ruleset(raw_ruleset);
        auto context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};
        // No m.mentions.room field on the event below, and no notification
        // power level recorded for "room" -- .m.rule.is_room_mention's
        // sender_notification_permission condition would fail closed here
        // even if content.m\.mentions.room were somehow present, so a
        // notify:true+highlight outcome can only come from the removed
        // roomnotif rule if it were still present.

        WHEN("the sender, who is not the receiving user, sends a plain message containing the literal text \"@room\"")
        {
            auto const event =
                make_event_with_body("@sender:example.org", "!room:example.org", "hey @room, check this out");
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the message still notifies via .m.rule.message, but is never highlighted")
            {
                // Positive counterpart first: the message is a normal
                // m.room.message and DOES still notify -- the fix removes
                // the false-positive HIGHLIGHT, not delivery of the message
                // itself. This keeps the highlight-absence check below from
                // vacuously passing because nothing matched at all.
                REQUIRE(result.notify);
                REQUIRE(result.matched_rule_id == ".m.rule.message");
                REQUIRE_FALSE(result.tweak_highlight);
            }
        }
    }
}

SCENARIO("A message body containing the recipient's display name alone no longer produces a highlighted "
         "notification",
         "[push]")
{
    GIVEN("the real default ruleset and a receiving user with a known display name")
    {
        auto const raw_ruleset = merovingian::homeserver::default_push_ruleset("@receiver:example.org");
        auto const ruleset = merovingian::push::parse_push_ruleset(raw_ruleset);
        auto context = merovingian::push::PushEvaluationContext{"@receiver:example.org"};
        context.receiving_user_display_name = "Receiver";

        WHEN("the sender's message body contains the receiving user's display name as ordinary prose")
        {
            auto const event =
                make_event_with_body("@sender:example.org", "!room:example.org", "did you see what Receiver posted?");
            auto const result = merovingian::push::evaluate_push_rules(ruleset, event, context);

            THEN("the message still notifies via .m.rule.message, but is never highlighted")
            {
                REQUIRE(result.notify);
                REQUIRE(result.matched_rule_id == ".m.rule.message");
                REQUIRE_FALSE(result.tweak_highlight);
            }
        }
    }
}
