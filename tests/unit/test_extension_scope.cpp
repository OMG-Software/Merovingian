// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// `extension_scope_rooms` (MSC4508 "Common extension semantics", ADR-0858): which rooms a sliding sync extension
// applies to, from its `lists` and `rooms` keys; `joined_extension_scope_rooms` keeps the joined ones (ADR-0859).
// MSC4508 is not in Matrix v1.19, so these are project-level checks.

#include "merovingian/sync/ExtensionScope.hpp"
#include "merovingian/sync/ExtensionScopeSource.hpp"
#include "merovingian/sync/RoomAccess.hpp"

#include <catch2/catch_test_macros.hpp>

#include <functional>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace
{

using merovingian::sync::extension_scope_rooms;
using merovingian::sync::joined_extension_scope_rooms;
using merovingian::sync::RoomAccess;
using Names = std::optional<std::vector<std::string>>;

// A scope key holding exactly `entries`; `named({})` is the empty array.
[[nodiscard]] auto named(std::vector<std::string> entries) -> Names
{
    return Names{std::move(entries)};
}

// Two lists that share a room, and two room subscriptions, one of them also in a list.
[[nodiscard]] auto list_windows() -> std::map<std::string, std::vector<std::string>>
{
    return {
        {"dms", {"!a:x", "!b:x"}},
        {"all", {"!b:x", "!c:x"}}
    };
}

[[nodiscard]] auto subscriptions() -> std::vector<std::string>
{
    return {"!c:x", "!s:x"};
}

} // namespace

SCENARIO("an extension with neither key applies to every list and every subscription", "[sync][extension-scope]")
{
    GIVEN("two lists and two subscriptions")
    {
        WHEN("both keys are absent, or both hold \"*\"")
        {
            auto const absent = extension_scope_rooms(std::nullopt, std::nullopt, list_windows(), subscriptions());
            auto const star = extension_scope_rooms(named({"*"}), named({"*"}), list_windows(), subscriptions());
            THEN("every room is in scope once, list rooms by list key first, then the subscriptions")
            {
                auto const expected = std::vector<std::string>{"!b:x", "!c:x", "!a:x", "!s:x"};
                REQUIRE(absent == expected);
                REQUIRE(star == expected);
            }
        }
    }
}

SCENARIO("an extension's lists key names the lists it applies to", "[sync][extension-scope]")
{
    GIVEN("two lists and two subscriptions")
    {
        WHEN("lists names one list and rooms is an empty array")
        {
            auto const scope = extension_scope_rooms(named({"dms"}), named({}), list_windows(), subscriptions());
            THEN("only that list's rooms are in scope")
            {
                REQUIRE(scope == std::vector<std::string>{"!a:x", "!b:x"});
            }
        }

        WHEN("lists is an empty array and rooms is absent")
        {
            auto const scope = extension_scope_rooms(named({}), std::nullopt, list_windows(), subscriptions());
            THEN("only the subscriptions are in scope")
            {
                REQUIRE(scope == subscriptions());
            }
        }

        WHEN("lists names a list the request does not hold")
        {
            auto const scope = extension_scope_rooms(named({"missing"}), named({}), list_windows(), subscriptions());
            THEN("nothing is in scope")
            {
                REQUIRE(scope.empty());
            }
        }
    }
}

SCENARIO("an extension's rooms key reaches only rooms the request subscribed to", "[sync][extension-scope]")
{
    GIVEN("two lists and two subscriptions")
    {
        WHEN("rooms names a subscription, a list room and an unknown room, with lists empty")
        {
            auto const scope = extension_scope_rooms(named({}), named({"!s:x", "!a:x", "!unknown:x"}), list_windows(),
                                                     subscriptions());
            THEN("only the subscription is in scope: naming a room does not subscribe to it")
            {
                REQUIRE(scope == std::vector<std::string>{"!s:x"});
            }
        }

        WHEN("rooms names a subscription that is also in a named list")
        {
            auto const scope = extension_scope_rooms(named({"all"}), named({"!c:x"}), list_windows(), subscriptions());
            THEN("the room is in scope once")
            {
                REQUIRE(scope == std::vector<std::string>{"!b:x", "!c:x"});
            }
        }
    }
}

// CSAZ-1 (ADR-0859): naming a room, in a list window or a subscription, is no entitlement; every room-scoped extension
// serves only the rooms of its scope the user has joined.
SCENARIO("an extension serves only the joined rooms of its scope", "[sync][extension-scope]")
{
    GIVEN("two lists and two subscriptions, where the user is joined to two rooms, invited to one and left another")
    {
        auto const source = merovingian::sync::ExtensionScopeSource{list_windows(), subscriptions()};
        auto const access = std::map<std::string, RoomAccess, std::less<>>{
            {"!a:x", RoomAccess::joined },
            {"!b:x", RoomAccess::invited},
            {"!c:x", RoomAccess::joined },
            {"!s:x", RoomAccess::none   },
        };

        WHEN("every room is in scope")
        {
            auto const rooms = joined_extension_scope_rooms(std::nullopt, std::nullopt, source, access);
            THEN("only the joined rooms are kept, in scope order")
            {
                REQUIRE(rooms == std::vector<std::string>{"!c:x", "!a:x"});
            }
        }

        WHEN("the scope is one list and no subscription")
        {
            auto const rooms = joined_extension_scope_rooms(named({"dms"}), named({}), source, access);
            THEN("only that list's joined room is kept")
            {
                REQUIRE(rooms == std::vector<std::string>{"!a:x"});
            }
        }

        WHEN("the user holds no membership at all")
        {
            auto const rooms = joined_extension_scope_rooms(std::nullopt, std::nullopt, source, {});
            THEN("nothing is kept")
            {
                REQUIRE(rooms.empty());
            }
        }
    }
}
