// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Unit tests for merovingian::trust_safety::ignore_list — the pure
// parsing/decision helpers behind Matrix v1.19 CS API "Ignoring Users"
// enforcement. Spec-level MUST/SHOULD coverage (the actual /sync,
// /messages, /context, and sliding sync behaviour) lives in
// tests/conformance/test_ignoring_users_conformance.cpp; this file isolates
// the module in memory with no I/O, per tests/unit/AGENTS.md.

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/trust_safety/ignore_list.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <unordered_set>

namespace
{

using merovingian::database::PersistentAccountData;
using merovingian::database::PersistentStore;

} // namespace

// Spec: Matrix Client-Server API v1.19 §Ignoring Users — Events
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#ignoring-users
SCENARIO("parse_ignored_user_list extracts the ignored_users key map", "[trust_safety][ignore_list]")
{
    GIVEN("a well-formed m.ignored_user_list content body naming two users")
    {
        auto const content = std::string{R"({"ignored_users":{"@bob:example.org":{},"@carol:example.org":{}}})"};

        WHEN("it is parsed")
        {
            auto const ignored = merovingian::trust_safety::parse_ignored_user_list(content);

            THEN("both user IDs are present and nothing else is")
            {
                REQUIRE(ignored.size() == 2U);
                REQUIRE(ignored.contains("@bob:example.org"));
                REQUIRE(ignored.contains("@carol:example.org"));
                REQUIRE_FALSE(ignored.contains("@dave:example.org"));
            }
        }
    }
}

SCENARIO("parse_ignored_user_list fails safe on malformed input", "[trust_safety][ignore_list][security]")
{
    GIVEN("content bodies that are absent, empty, not JSON, or shaped wrong")
    {
        WHEN("content is empty")
        {
            THEN("the result is an empty set, not an error")
            {
                REQUIRE(merovingian::trust_safety::parse_ignored_user_list("").empty());
            }
        }
        WHEN("content is not valid JSON")
        {
            THEN("the result is an empty set")
            {
                REQUIRE(merovingian::trust_safety::parse_ignored_user_list("{not json").empty());
            }
        }
        WHEN("content is a JSON object missing the ignored_users key")
        {
            THEN("the result is an empty set")
            {
                REQUIRE(merovingian::trust_safety::parse_ignored_user_list(R"({"unrelated":true})").empty());
            }
        }
        WHEN("ignored_users is present but is the wrong type (a string, not an object)")
        {
            THEN("the result is an empty set")
            {
                REQUIRE(
                    merovingian::trust_safety::parse_ignored_user_list(R"({"ignored_users":"not an object"})").empty());
            }
        }
        WHEN("the top-level value is a JSON array, not an object")
        {
            THEN("the result is an empty set")
            {
                REQUIRE(merovingian::trust_safety::parse_ignored_user_list(R"(["not","an","object"])").empty());
            }
        }
    }
}

SCENARIO("resolve_ignored_users reads the caller's global m.ignored_user_list row", "[trust_safety][ignore_list]")
{
    GIVEN("a store with alice's global ignore list and an unrelated room-scoped row of the same type")
    {
        auto store = PersistentStore{};
        store.account_data.push_back(PersistentAccountData{"@alice:example.org", std::string{}, "m.ignored_user_list",
                                                           R"({"ignored_users":{"@bob:example.org":{}}})", 1U});
        // Room-scoped account data of the SAME event_type must never be
        // mistaken for the global ignore list (room_id is non-empty here).
        store.account_data.push_back(PersistentAccountData{"@alice:example.org", "!room:example.org",
                                                           "m.ignored_user_list",
                                                           R"({"ignored_users":{"@carol:example.org":{}}})", 2U});

        WHEN("alice's ignore set is resolved")
        {
            auto const ignored = merovingian::trust_safety::resolve_ignored_users(store, "@alice:example.org");

            THEN("only the global row's user is present")
            {
                REQUIRE(ignored.size() == 1U);
                REQUIRE(ignored.contains("@bob:example.org"));
                REQUIRE_FALSE(ignored.contains("@carol:example.org"));
            }
        }
    }

    GIVEN("a store with no m.ignored_user_list row for the user at all")
    {
        auto const store = PersistentStore{};

        WHEN("the ignore set is resolved")
        {
            THEN("it fails safe to an empty set rather than erroring")
            {
                REQUIRE(merovingian::trust_safety::resolve_ignored_users(store, "@alice:example.org").empty());
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19 §Ignoring Users — Server behaviour
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#ignoring-users
//
// Spec MUST: "Servers must still send state events sent by ignored users to
// clients."
SCENARIO("is_delivery_suppressed never withholds a state event from an ignored sender", "[trust_safety][ignore_list]")
{
    GIVEN("bob is ignored and sends a state event")
    {
        auto const ignored = std::unordered_set<std::string>{"@bob:example.org"};

        WHEN("suppression is evaluated with is_state_event=true")
        {
            auto const suppressed =
                merovingian::trust_safety::is_delivery_suppressed(ignored, "@bob:example.org", /*is_state_event=*/true);

            THEN("the state event is not suppressed")
            {
                REQUIRE_FALSE(suppressed);
            }
        }
    }
}

// Spec MUST: "Servers must not send room invites from ignored users to
// clients." — this overrides the state-event exemption above even though an
// invite is itself an m.room.member state event.
SCENARIO("is_delivery_suppressed withholds a new-room invite from an ignored sender even though it is a state event",
         "[trust_safety][ignore_list]")
{
    GIVEN("bob is ignored and extends a room invite")
    {
        auto const ignored = std::unordered_set<std::string>{"@bob:example.org"};

        WHEN("suppression is evaluated with is_state_event=true and is_new_room_invite=true")
        {
            auto const suppressed = merovingian::trust_safety::is_delivery_suppressed(
                ignored, "@bob:example.org", /*is_state_event=*/true, /*is_new_room_invite=*/true);

            THEN("the invite is suppressed")
            {
                REQUIRE(suppressed);
            }
        }
    }
}

SCENARIO("is_delivery_suppressed withholds a non-state event from an ignored sender", "[trust_safety][ignore_list]")
{
    GIVEN("bob is ignored and sends an ordinary message")
    {
        auto const ignored = std::unordered_set<std::string>{"@bob:example.org"};

        WHEN("suppression is evaluated with is_state_event=false")
        {
            auto const suppressed = merovingian::trust_safety::is_delivery_suppressed(ignored, "@bob:example.org",
                                                                                      /*is_state_event=*/false);

            THEN("the message is suppressed")
            {
                REQUIRE(suppressed);
            }
        }
    }
}

SCENARIO("is_delivery_suppressed never withholds anything from a sender who is not ignored",
         "[trust_safety][ignore_list]")
{
    GIVEN("carol is not on alice's ignore list")
    {
        auto const ignored = std::unordered_set<std::string>{"@bob:example.org"};

        WHEN("suppression is evaluated for carol's message, state event, and invite")
        {
            auto const message_suppressed = merovingian::trust_safety::is_delivery_suppressed(
                ignored, "@carol:example.org", /*is_state_event=*/false);
            auto const state_suppressed = merovingian::trust_safety::is_delivery_suppressed(
                ignored, "@carol:example.org", /*is_state_event=*/true);
            auto const invite_suppressed = merovingian::trust_safety::is_delivery_suppressed(
                ignored, "@carol:example.org", /*is_state_event=*/true, /*is_new_room_invite=*/true);

            THEN("none of them are suppressed")
            {
                REQUIRE_FALSE(message_suppressed);
                REQUIRE_FALSE(state_suppressed);
                REQUIRE_FALSE(invite_suppressed);
            }
        }
    }
}

SCENARIO("is_delivery_suppressed fails safe with an empty ignore set", "[trust_safety][ignore_list][security]")
{
    GIVEN("an empty ignore set, standing in for a missing or malformed m.ignored_user_list")
    {
        auto const ignored = std::unordered_set<std::string>{};

        WHEN("suppression is evaluated for any sender and event shape")
        {
            THEN("nothing is ever suppressed")
            {
                REQUIRE_FALSE(merovingian::trust_safety::is_delivery_suppressed(ignored, "@bob:example.org", false));
                REQUIRE_FALSE(merovingian::trust_safety::is_delivery_suppressed(ignored, "@bob:example.org", true));
                REQUIRE_FALSE(
                    merovingian::trust_safety::is_delivery_suppressed(ignored, "@bob:example.org", true, true));
            }
        }
    }
}

SCENARIO("event_json_is_state_event discriminates on state_key presence, not its value", "[trust_safety][ignore_list]")
{
    GIVEN("a message event with no state_key")
    {
        auto const json = std::string{R"({"type":"m.room.message","sender":"@bob:example.org","content":{}})"};
        WHEN("classified")
        {
            THEN("it is not a state event")
            {
                REQUIRE_FALSE(merovingian::trust_safety::event_json_is_state_event(json));
            }
        }
    }

    GIVEN("a state event whose state_key is the empty string")
    {
        auto const json =
            std::string{R"({"type":"m.room.name","state_key":"","sender":"@bob:example.org","content":{}})"};
        WHEN("classified")
        {
            THEN("it IS a state event — presence of the key matters, not its value")
            {
                REQUIRE(merovingian::trust_safety::event_json_is_state_event(json));
            }
        }
    }

    GIVEN("malformed JSON")
    {
        WHEN("classified")
        {
            THEN("it fails safe to 'not a state event' rather than throwing")
            {
                REQUIRE_FALSE(merovingian::trust_safety::event_json_is_state_event("{not json"));
            }
        }
    }
}
