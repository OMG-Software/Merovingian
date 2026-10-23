// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// homeserver::push_room_facts_from: a room's `notifications` levels are read in the encoding the
// room's version allows, as the authorization rules read them. Spec: rooms/v9.md
// "m.room.power_levels events accept values as strings ... This includes the nested values within
// the events, notifications and users properties"; rooms/v10.md "power levels MUST NOT be
// represented as strings within this room version".

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/homeserver/push_room_facts.hpp"
#include "merovingian/push/push_rules.hpp"

#include <catch2/catch_test_macros.hpp>

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>

namespace
{

constexpr auto alice = std::string_view{"@alice:example.org"};
constexpr auto bob = std::string_view{"@bob:example.org"};

[[nodiscard]] auto parse(std::string const& json) -> merovingian::canonicaljson::Value
{
    auto parsed = merovingian::canonicaljson::parse_lossless(json);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    return std::move(parsed.value);
}

// Only the room-mention rule, so `notify` is exactly whether the sender may notify the room.
[[nodiscard]] auto room_mention_only() -> merovingian::push::PushRuleset
{
    auto const value = parse(R"({"override":[{"rule_id":".m.rule.is_room_mention","default":true,"enabled":true,
        "conditions":[{"kind":"event_property_is","key":"content.m\\.mentions.room","value":true},
                      {"kind":"sender_notification_permission","key":"room"}],
        "actions":["notify",{"set_tweak":"highlight"}]}]})");
    return merovingian::push::parse_push_ruleset(std::get<merovingian::canonicaljson::Object>(value.storage()));
}

// Whether bob's @room in a room of `room_version` with these power levels notifies alice.
[[nodiscard]] auto room_mention_notifies(std::string const& power_levels_content, std::string const& room_version)
    -> bool
{
    auto const facts = merovingian::homeserver::push_room_facts_from(
        parse(R"({"type":"m.room.power_levels","state_key":"","content":)" + power_levels_content + "}"),
        std::optional<std::string>{room_version}, 2U);
    auto const event = parse(std::string{R"({"type":"m.room.message","sender":")"} + std::string{bob} +
                             R"(","content":{"msgtype":"m.text","body":"all","m.mentions":{"room":true}}})");
    auto const context = merovingian::homeserver::push_evaluation_context(facts, alice, "", bob);
    return merovingian::push::evaluate_push_rules(room_mention_only(), event, context).notify;
}

} // namespace

SCENARIO("A string notifications level is read as the room's version reads power levels", "[push][r15]")
{
    GIVEN("a version 9 room whose notifications.room is the string \"100\"")
    {
        auto const content = std::string{R"({"users":{"@bob:example.org":50},"notifications":{"room":"100"}})"};
        auto const raised = std::string{R"({"users":{"@bob:example.org":"100"},"notifications":{"room":"100"}})"};

        WHEN("bob sends an @room at level 50, and at level 100")
        {
            auto const at_50 = room_mention_notifies(content, "9");
            auto const at_100 = room_mention_notifies(raised, "9");

            THEN("the threshold is 100: level 50 does not notify and level 100 does")
            {
                REQUIRE_FALSE(at_50);
                REQUIRE(at_100);
            }
        }
    }

    GIVEN("the same power levels in rooms of version 10 and 12, where a string level is invalid")
    {
        auto const content = std::string{R"({"users":{"@bob:example.org":50},"notifications":{"room":"100"}})"};

        WHEN("bob sends an @room at level 50")
        {
            auto const v10 = room_mention_notifies(content, "10");
            auto const v12 = room_mention_notifies(content, "12");

            THEN("the authorization rules would not read the entry, so the default of 50 applies and it notifies")
            {
                REQUIRE(v10);
                REQUIRE(v12);
            }
        }
    }
}

SCENARIO("An integer notifications level is read the same in every room version", "[push][r15]")
{
    GIVEN("notifications.room 100 in rooms of version 9 and 12")
    {
        auto const content = std::string{R"({"users":{"@bob:example.org":50},"notifications":{"room":100}})"};
        auto const raised = std::string{R"({"users":{"@bob:example.org":100},"notifications":{"room":100}})"};

        WHEN("bob sends an @room at level 50, and at level 100")
        {
            THEN("level 50 does not notify and level 100 does, in both")
            {
                REQUIRE_FALSE(room_mention_notifies(content, "9"));
                REQUIRE_FALSE(room_mention_notifies(content, "12"));
                REQUIRE(room_mention_notifies(raised, "9"));
                REQUIRE(room_mention_notifies(raised, "12"));
            }
        }
    }

    GIVEN("no notifications object at all")
    {
        auto const content = std::string{R"({"users":{"@bob:example.org":50}})"};

        WHEN("bob sends an @room at level 50")
        {
            THEN("the default room level of 50 applies and it notifies")
            {
                REQUIRE(room_mention_notifies(content, "12"));
            }
        }
    }
}
