// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Unit tests for federation::validate_invite_room_state: the refusals that happen before any signature is
// checked, and the room versions it accepts as they arrive.
//
// Spec (server-server-api.md, PUT /_matrix/federation/v2/invite): `invite_room_state` "MUST contain the
// `m.room.create` event for the room", each entry formatted according to the room version, in the room of
// the invite; the server answers M_INVALID_PARAM (400) otherwise. For room versions 1 through 11 the
// validation is optional and entries are accepted as they arrive.

#include "merovingian/events/Limits.hpp"
#include "merovingian/federation/FederationDecision.hpp"
#include "merovingian/federation/FederationKeyRecord.hpp"
#include "merovingian/federation/InboundRequest.hpp"
#include "merovingian/federation/InviteRoomState.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace
{

constexpr auto room_id = std::string_view{"!abc:remote.example"};

struct Outcome final
{
    merovingian::federation::FederationDecision decision{};
    std::size_t key_lookups{0U};
};

[[nodiscard]] auto validate(std::string_view version, std::vector<std::string> const& entries) -> Outcome
{
    auto outcome = Outcome{};
    auto const resolver = [&outcome](std::string_view, std::string_view) {
        ++outcome.key_lookups;
        return merovingian::federation::VerificationKeyResolution{};
    };
    outcome.decision = merovingian::federation::validate_invite_room_state(
        room_id, version, entries, std::optional<merovingian::federation::FederationKeyRecord>{}, resolver);
    return outcome;
}

} // namespace

SCENARIO("Invite room state for room versions before 12 is accepted as it arrives", "[federation][invite][unit]")
{
    GIVEN("stripped and malformed entries for a version 11 room")
    {
        auto const entries = std::vector<std::string>{
            R"({"type":"m.room.create","state_key":"","content":{},"sender":"@a:b"})", "not json"};

        WHEN("the invite is validated")
        {
            auto const outcome = validate("11", entries);

            THEN("it is accepted without a signature lookup")
            {
                REQUIRE(outcome.decision.accepted);
                REQUIRE(outcome.decision.status == 200U);
                REQUIRE(outcome.key_lookups == 0U);
            }
        }
    }

    GIVEN("a version 11 invite with more entries than a room's stripped state can hold")
    {
        auto const entries =
            std::vector<std::string>(merovingian::federation::max_invite_room_state_entries + 1U, "{}");

        WHEN("the invite is validated")
        {
            auto const outcome = validate("11", entries);

            THEN("it is refused before any signature lookup: the count bounds every room version (ADR-0619)")
            {
                REQUIRE_FALSE(outcome.decision.accepted);
                REQUIRE(outcome.decision.status == 400U);
                REQUIRE(outcome.key_lookups == 0U);
            }
        }
    }

    GIVEN("a version 11 invite with exactly as many entries as allowed")
    {
        auto const entries = std::vector<std::string>(merovingian::federation::max_invite_room_state_entries, "{}");

        WHEN("the invite is validated")
        {
            auto const outcome = validate("11", entries);

            THEN("it is accepted as it arrives")
            {
                REQUIRE(outcome.decision.accepted);
            }
        }
    }

    GIVEN("a version 11 invite with one entry over the event size limit")
    {
        auto const entries = std::vector<std::string>{std::string(merovingian::events::max_event_size_bytes + 1U, 'x')};

        WHEN("the invite is validated")
        {
            auto const outcome = validate("11", entries);

            THEN("it is refused")
            {
                REQUIRE_FALSE(outcome.decision.accepted);
                REQUIRE(outcome.decision.status == 400U);
            }
        }
    }

    GIVEN("a room version this server has no policy for")
    {
        WHEN("the invite is validated")
        {
            auto const outcome = validate("not-a-version", {});

            THEN("it is a server error, not an accepted invite")
            {
                REQUIRE_FALSE(outcome.decision.accepted);
                REQUIRE(outcome.decision.status == 500U);
            }
        }
    }
}

SCENARIO("Invite room state for room version 12 is refused when it is not an honest stripped-state set",
         "[federation][invite][unit]")
{
    GIVEN("an empty invite_room_state")
    {
        WHEN("the invite is validated")
        {
            auto const outcome = validate("12", {});

            THEN("it is refused for lacking the create event")
            {
                REQUIRE_FALSE(outcome.decision.accepted);
                REQUIRE(outcome.decision.status == 400U);
                REQUIRE(outcome.decision.reason.find("m.room.create") != std::string::npos);
            }
        }
    }

    GIVEN("exactly the maximum number of malformed entries, and one more")
    {
        auto at_limit = std::vector<std::string>(merovingian::federation::max_invite_room_state_entries, "{}");
        auto over_limit = at_limit;
        over_limit.emplace_back("{}");

        WHEN("each list is validated")
        {
            auto const at = validate("12", at_limit);
            auto const over = validate("12", over_limit);

            THEN("the list at the limit is looked at (and fails on its first entry), the longer one is refused unread")
            {
                REQUIRE(at.decision.status == 400U);
                REQUIRE(at.decision.reason.find("not formatted") != std::string::npos);
                REQUIRE(over.decision.status == 400U);
                REQUIRE(over.decision.reason.find("more entries") != std::string::npos);
                REQUIRE(over.key_lookups == 0U);
            }
        }
    }

    GIVEN("an entry larger than the event size limit")
    {
        auto const entries = std::vector<std::string>{std::string(merovingian::events::max_event_size_bytes + 1U, ' ')};

        WHEN("the invite is validated")
        {
            auto const outcome = validate("12", entries);

            THEN("it is refused without parsing or a signature lookup")
            {
                REQUIRE(outcome.decision.status == 400U);
                REQUIRE(outcome.decision.reason.find("size limit") != std::string::npos);
                REQUIRE(outcome.key_lookups == 0U);
            }
        }
    }

    GIVEN("a stripped event, invalid JSON and a non-object entry")
    {
        auto const stripped =
            std::vector<std::string>{R"({"type":"m.room.create","state_key":"","content":{},"sender":"@a:b"})"};
        auto const garbage = std::vector<std::string>{"{\"type\":"};
        auto const array = std::vector<std::string>{"[]"};

        WHEN("each is validated")
        {
            auto const a = validate("12", stripped);
            auto const b = validate("12", garbage);
            auto const c = validate("12", array);

            THEN("each is refused as not formatted according to the room version, with no key lookup")
            {
                for (auto const* outcome : {&a, &b, &c})
                {
                    REQUIRE_FALSE(outcome->decision.accepted);
                    REQUIRE(outcome->decision.status == 400U);
                    REQUIRE(outcome->decision.reason.find("not formatted") != std::string::npos);
                    REQUIRE(outcome->key_lookups == 0U);
                }
            }
        }
    }
}
