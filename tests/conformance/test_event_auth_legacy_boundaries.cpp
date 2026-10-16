// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <string>
#include <string_view>
#include <utility>

namespace
{
using namespace merovingian;

[[nodiscard]] auto parse_event(std::string_view json) -> canonicaljson::Value
{
    auto parsed = canonicaljson::parse_lossless(json);
    REQUIRE(parsed.error == canonicaljson::ParseError::none);
    return std::move(parsed.value);
}

[[nodiscard]] auto room_auth(std::string_view version) -> events::AuthEventMap
{
    auto auth = events::AuthEventMap{};
    auth.create = parse_event(
        R"({"type":"m.room.create","state_key":"","sender":"@admin:example.org","content":{"creator":"@admin:example.org","room_version":")" +
        std::string{version} + R"("}})");
    auth.sender_member = parse_event(
        R"({"type":"m.room.member","state_key":"@mod:example.org","sender":"@mod:example.org","content":{"membership":"join"}})");
    auth.power_levels = parse_event(
        R"({"type":"m.room.power_levels","state_key":"","content":{"invite":0,"users":{"@mod:example.org":50}}})");
    return auth;
}
} // namespace

// Spec: Matrix v1.19, rooms/v3.md and rooms/v12.md — Authorization rules,
// "If content has a third_party_invite property" and "does not have a signed property, reject".
SCENARIO("An invite cannot bypass third-party authorization with a malformed present property",
         "[conformance][events][security][evt-10]")
{
    GIVEN("a joined inviter with invite power in a supported room version")
    {
        auto const version = GENERATE("3", "4", "5", "6", "7", "8", "9", "10", "11", "12");
        auto const malformed = GENERATE(R"("x")", "null", "true", "42", "[]", "{}");
        CAPTURE(version, malformed);
        auto const auth = room_auth(version);
        auto const policy = *merovingian::rooms::find_room_version_policy(version);
        auto const event = parse_event(
            R"({"type":"m.room.member","state_key":"@bob:example.org","sender":"@mod:example.org","content":{"membership":"invite","third_party_invite":)" +
            std::string{malformed} + "}}");

        WHEN("the malformed third-party invite is authorized")
        {
            auto const result = merovingian::events::authorize_event_against_auth_events(event, policy, auth);
            THEN("the present property triggers third-party checks and the invite is refused")
            {
                // Spec MUST: absent signed data is rejected, not treated as an ordinary invite.
                REQUIRE_FALSE(result.allowed);
            }
        }
        WHEN("an ordinary invite has no third_party_invite property")
        {
            auto const ordinary = parse_event(
                R"({"type":"m.room.member","state_key":"@bob:example.org","sender":"@mod:example.org","content":{"membership":"invite"}})");
            auto const result = merovingian::events::authorize_event_against_auth_events(ordinary, policy, auth);
            THEN("the usual invite permission remains usable")
            {
                // Spec MUST: joined senders with invite power may send ordinary invites.
                REQUIRE(result.allowed);
            }
        }
    }
}

// Spec: Matrix v1.19, rooms/v9.md — m.room.power_levels events accept values
// as strings, including the nested events map; Authorization rules 7.
SCENARIO("Legacy string event thresholds govern both state and message authorization",
         "[conformance][events][security][evt-11]")
{
    GIVEN("a moderator at level 50 and a legacy events-map threshold at level 100")
    {
        auto const version = GENERATE("3", "4", "5", "6", "7", "8", "9");
        auto const type = GENERATE("m.room.topic", "m.room.message");
        auto const threshold = GENERATE(R"("100")", R"(" +00100 ")", "100");
        CAPTURE(version, type, threshold);
        auto auth = room_auth(version);
        auth.power_levels = parse_event(
            R"({"type":"m.room.power_levels","state_key":"","content":{"users":{"@mod:example.org":50},"events":{")" +
            std::string{type} + "\":" + threshold + "}}}");
        auto const policy = *merovingian::rooms::find_room_version_policy(version);
        auto const state_key = std::string{type} == "m.room.topic" ? R"(,"state_key":"")" : "";
        auto const event = parse_event(R"({"type":")" + std::string{type} +
                                       R"(","sender":"@mod:example.org","content":{})" + state_key + "}");
        WHEN("the moderator submits the event")
        {
            auto const result = merovingian::events::authorize_event_against_auth_events(event, policy, auth);
            THEN("the explicit threshold is enforced instead of falling back to the default")
            {
                // Spec MUST: reject if the required event-type level exceeds the sender's level.
                REQUIRE_FALSE(result.allowed);
            }
        }
        WHEN("the threshold is lowered to the moderator's own level")
        {
            auth.power_levels = parse_event(
                R"({"type":"m.room.power_levels","state_key":"","content":{"users":{"@mod:example.org":50},"events":{")" +
                std::string{type} + R"(":"50"}}})");
            auto const result = merovingian::events::authorize_event_against_auth_events(event, policy, auth);
            THEN("equality is accepted for the legacy string threshold")
            {
                // Spec MUST: only levels greater than the sender's cause rejection.
                REQUIRE(result.allowed);
            }
        }
    }
}

// Spec: Matrix v1.19, rooms/v3.md, rooms/v4.md and rooms/v5.md — Authorization
// rules 4: m.room.aliases requires state_key equal to sender's domain, then allows.
SCENARIO("Legacy aliases are authorized by their sender domain rather than membership or power",
         "[conformance][events][security][evt-12a]")
{
    GIVEN("an aliases event in a room version with the special domain rule")
    {
        auto const version = GENERATE("3", "4", "5");
        auto const key = GENERATE("example.org", "attacker.example", "missing");
        auto const joined = GENERATE(true, false);
        CAPTURE(version, key, joined);
        auto auth = room_auth(version);
        if (!joined)
        {
            auth.sender_member = {};
        }
        auto const policy = *merovingian::rooms::find_room_version_policy(version);
        auto const key_json =
            std::string{key} == "missing" ? std::string{} : R"(,"state_key":")" + std::string{key} + R"(")";
        auto const event =
            parse_event(R"({"type":"m.room.aliases","sender":"@mod:example.org","content":{})" + key_json + "}");
        WHEN("the aliases event is authorized")
        {
            auto const result = merovingian::events::authorize_event_against_auth_events(event, policy, auth);
            THEN("only a present state_key matching the complete sender domain is allowed")
            {
                // Spec MUST: matching domains allow; absent or mismatched keys reject.
                REQUIRE(result.allowed == (std::string{key} == "example.org"));
            }
        }
    }
}

// Spec: Matrix v1.19, rooms/v6.md — m.room.aliases removed from special auth rules.
SCENARIO("Newer aliases events retain ordinary membership and state power checks",
         "[conformance][events][security][evt-12a]")
{
    GIVEN("an unjoined aliases sender whose state_key matches its domain")
    {
        auto const version = GENERATE("6", "7", "8", "9", "10", "11", "12");
        auto auth = room_auth(version);
        auth.sender_member = {};
        auto const policy = *merovingian::rooms::find_room_version_policy(version);
        auto const event = parse_event(
            R"({"type":"m.room.aliases","state_key":"example.org","sender":"@mod:example.org","content":{}})");
        WHEN("the event is authorized")
        {
            auto const result = merovingian::events::authorize_event_against_auth_events(event, policy, auth);
            THEN("the legacy domain shortcut does not apply")
            {
                // Spec MUST: a non-member cannot send ordinary state events in v6+.
                REQUIRE_FALSE(result.allowed);
            }
        }
    }
}
