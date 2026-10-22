// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// homeserver::PushRuleUnreadClassifier: each room's push-rule facts (power levels read by the
// room's version, notification levels, joined member count, the user's display name in the
// room) decide notify and highlight per room, and are gathered without a whole-table walk per
// room (ADR-0205, ADR-0207).

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/push_rule_unread_classifier.hpp"
#include "merovingian/push/push_rules.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <variant>

namespace
{

constexpr auto alice = std::string_view{"@alice:example.org"};
constexpr auto bob = std::string_view{"@bob:example.org"};

// A room mention from a sender with permission, the user's display name in the body, and a room of
// exactly three joined members each highlight; any other message only notifies.
constexpr auto ruleset_json = std::string_view{R"({
  "override": [
    {"rule_id": ".m.rule.is_room_mention", "default": true, "enabled": true,
     "conditions": [{"kind": "event_property_is", "key": "content.m\\.mentions.room", "value": true},
                    {"kind": "sender_notification_permission", "key": "room"}],
     "actions": ["notify", {"set_tweak": "highlight"}]},
    {"rule_id": "name", "default": false, "enabled": true,
     "conditions": [{"kind": "contains_display_name"}],
     "actions": ["notify", {"set_tweak": "highlight"}]},
    {"rule_id": "trio", "default": false, "enabled": true,
     "conditions": [{"kind": "room_member_count", "is": "3"}],
     "actions": ["notify", {"set_tweak": "highlight"}]}
  ],
  "underride": [
    {"rule_id": ".m.rule.message", "default": true, "enabled": true,
     "conditions": [{"kind": "event_match", "key": "type", "pattern": "m.room.message"}],
     "actions": ["notify"]}
  ]
})"};

[[nodiscard]] auto ruleset() -> merovingian::push::PushRuleset
{
    auto const parsed = merovingian::canonicaljson::parse_lossless(ruleset_json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return merovingian::push::parse_push_ruleset(std::get<merovingian::canonicaljson::Object>(parsed.value.storage()));
}

auto add_state(merovingian::database::PersistentStore& store, std::string_view room_id, std::string event_id,
               std::string_view type, std::string_view state_key, std::string const& content) -> void
{
    auto event = merovingian::database::PersistentEvent{};
    event.event_id = event_id;
    event.room_id = std::string{room_id};
    event.sender_user_id = std::string{bob};
    event.json = std::string{R"({"type":")"} + std::string{type} + R"(","state_key":")" + std::string{state_key} +
                 R"(","content":)" + content + "}";
    event.stream_ordering = 1U;
    store.events.push_back(std::move(event));
    store.state.push_back({std::string{room_id}, std::string{type}, std::string{state_key}, std::move(event_id)});
}

auto join(merovingian::database::PersistentStore& store, std::string_view room_id, std::string_view user) -> void
{
    store.memberships.push_back({std::string{room_id}, std::string{user}, "join", 1U});
}

[[nodiscard]] auto message(std::string const& content) -> merovingian::canonicaljson::Value
{
    auto parsed = merovingian::canonicaljson::parse_lossless(std::string{R"({"type":"m.room.message","sender":")"} +
                                                             std::string{bob} + R"(","content":)" + content + "}");
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return std::move(parsed.value);
}

} // namespace

SCENARIO("The unread classifier decides each room by that room's own push-rule facts", "[push][r15][push-badge]")
{
    GIVEN("six rooms alice is joined to, differing in power levels, room version, display name and size")
    {
        auto store = merovingian::database::PersistentStore{};
        store.profiles.push_back({std::string{alice}, "Prof", ""});
        for (auto const* room : {"!high:x", "!low:x", "!v5:x", "!named:x", "!profile:x", "!trio:x"})
        {
            join(store, room, alice);
        }
        // !high: bob may notify the room. !low: he may not (users_default 0, room level 50).
        add_state(store, "!high:x", "$pl-high", "m.room.power_levels", "",
                  R"({"users":{"@bob:example.org":50},"notifications":{"room":50}})");
        add_state(store, "!low:x", "$pl-low", "m.room.power_levels", "", R"({"users_default":0})");
        // !v5: a version 5 room, where a power level may be a string.
        add_state(store, "!v5:x", "$create-v5", "m.room.create", "", R"({"room_version":"5"})");
        add_state(store, "!v5:x", "$pl-v5", "m.room.power_levels", "", R"({"users":{"@bob:example.org":"50"}})");
        // !named: alice's member event names her "Ally"; !profile has none, so her profile's applies.
        add_state(store, "!named:x", "$member", "m.room.member", alice,
                  R"({"membership":"join","displayname":"Ally"})");
        join(store, "!trio:x", bob);
        join(store, "!trio:x", "@carol:example.org");

        auto const classifier = merovingian::homeserver::PushRuleUnreadClassifier{store, alice, ruleset()};
        auto const room_mention = message(R"({"msgtype":"m.text","body":"all","m.mentions":{"room":true}})");
        auto const says_ally = message(R"({"msgtype":"m.text","body":"hi Ally"})");
        auto const says_prof = message(R"({"msgtype":"m.text","body":"hi Prof"})");
        auto const plain = message(R"({"msgtype":"m.text","body":"hi"})");

        WHEN("one message is classified in the first room")
        {
            std::ignore = classifier.classify("!high:x", plain);
            auto const walks_for_one_room = classifier.table_walks();

            AND_WHEN("messages are classified in every room")
            {
                auto const high = classifier.classify("!high:x", room_mention);
                auto const low = classifier.classify("!low:x", room_mention);
                auto const v5 = classifier.classify("!v5:x", room_mention);
                auto const named_ally = classifier.classify("!named:x", says_ally);
                auto const named_prof = classifier.classify("!named:x", says_prof);
                auto const profile_prof = classifier.classify("!profile:x", says_prof);
                auto const trio = classifier.classify("!trio:x", plain);
                auto const solo = classifier.classify("!low:x", plain);

                THEN("a room mention highlights only where the sender's power level, read by the room's version, "
                     "allows it")
                {
                    REQUIRE(high.notify);
                    REQUIRE(high.highlight);
                    REQUIRE(low.notify);
                    REQUIRE_FALSE(low.highlight);
                    REQUIRE(v5.highlight);
                }

                THEN("the display name is the room's member event's, else the profile's")
                {
                    REQUIRE(named_ally.highlight);
                    REQUIRE_FALSE(named_prof.highlight);
                    REQUIRE(profile_prof.highlight);
                }

                THEN("the member count is the room's own joined members")
                {
                    REQUIRE(trio.highlight);
                    REQUIRE(solo.notify);
                    REQUIRE_FALSE(solo.highlight);
                }

                THEN("no table was walked again for the later rooms")
                {
                    REQUIRE(walks_for_one_room > 0U);
                    REQUIRE(classifier.table_walks() == walks_for_one_room);
                }
            }
        }
    }
}

SCENARIO("The unread classifier finds each room's join start from one walk of the events", "[push][r15]")
{
    GIVEN("alice joined two rooms, and left and rejoined the second")
    {
        auto store = merovingian::database::PersistentStore{};
        auto add_member = [&store](std::string event_id, std::string_view room_id, std::string_view membership,
                                   std::uint64_t ordering) {
            auto event = merovingian::database::PersistentEvent{};
            event.event_id = std::move(event_id);
            event.room_id = std::string{room_id};
            event.sender_user_id = std::string{alice};
            event.json = std::string{R"({"type":"m.room.member","state_key":")"} + std::string{alice} +
                         R"(","content":{"membership":")" + std::string{membership} + R"("}})";
            event.stream_ordering = ordering;
            event.status = "accepted";
            store.events.push_back(std::move(event));
        };
        add_member("$a1", "!a:x", "join", 1U);
        add_member("$b2", "!b:x", "join", 2U);
        add_member("$b3", "!b:x", "leave", 3U);
        add_member("$b4", "!b:x", "join", 4U);
        auto const classifier = merovingian::homeserver::PushRuleUnreadClassifier{store, alice, ruleset()};

        WHEN("each room's counting start is asked for")
        {
            auto const first = classifier.counted_after("!a:x");
            auto const walks_for_one_room = classifier.table_walks();
            auto const second = classifier.counted_after("!b:x");
            auto const unknown = classifier.counted_after("!c:x");

            THEN("they match current_join_start, and the later rooms walked no table")
            {
                REQUIRE(first == merovingian::homeserver::current_join_start(store, "!a:x", alice));
                REQUIRE(first == std::optional<std::uint64_t>{1U});
                REQUIRE(second == std::optional<std::uint64_t>{4U});
                REQUIRE_FALSE(unknown.has_value());
                REQUIRE(walks_for_one_room > 0U);
                REQUIRE(classifier.table_walks() == walks_for_one_room);
            }
        }
    }
}
