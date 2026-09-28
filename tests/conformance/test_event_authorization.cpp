// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX EVENT AUTHORIZATION CONFORMANCE TESTS                    |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.19, Room Version 6+ auth rules       |
// |  URL:  ../../docs/matrix-v1.19-spec/rooms/v6.md#authorization-rules      |
// |        ../../docs/matrix-v1.19-spec/server-server-api.md#auth-rules      |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST from the Matrix              |
// |  authorization rules or a hard security invariant. If a test fails:     |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |      spec itself has changed and citing the updated section.             |
// |                                                                         |
// |  The spec section is cited above each SCENARIO. Cross-check it before   |
// |  concluding that a failing assertion is wrong.                           |
// +-------------------------------------------------------------------------+

#include "merovingian/events/authorization.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

// 0.12.13 audit item 7: the scenarios that stood here exercised
// events::authorize_event and events::membership_policy_allows, which had no
// production callers and diverged from the spec for bans and knocks. Both
// were deleted with their tests. The auth rules the server enforces are
// events::authorize_event_against_auth_events, covered by
// tests/conformance/test_event_auth_rules.cpp.

// --- auth event selection -----------------------------------------------------
// Spec: Matrix Server-Server API v1.19 Sec. 4.4 auth_events
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#auth-events
// Spec: Matrix Room Version 12 (MSC4291)
// URL:  ../../docs/matrix-v1.19-spec/rooms/v12.md
//
// For m.room.member invite in room versions 1–11 the REQUIRED auth event set is:
//   {m.room.create, m.room.power_levels, m.room.join_rules, m.room.member(target)}
//
// In room version 12 the create event is implicit (the room ID IS the create event
// reference hash) and MUST NOT appear in auth_events. The v12 required set is:
//   {m.room.power_levels, m.room.join_rules, m.room.member(target)}
//
// Third-party invites add m.room.third_party_invite to whichever base set applies.
// A wrong or incomplete auth_events set causes remote auth failure.

// --- room versions 1–11 (create event is explicit) ---
SCENARIO("Auth event selection includes m.room.create for room versions 1–11",
         "[events][auth][auth-events][conformance]")
{
    GIVEN("a v10 m.room.member invite request")
    {
        auto normal_invite = merovingian::events::EventAuthorizationRequest{};
        normal_invite.room_version = "10";
        normal_invite.event_type = "m.room.member";
        normal_invite.state_key = "@bob:example.org";
        normal_invite.membership.requested_membership = merovingian::events::MembershipState::invite;

        auto third_party_invite = normal_invite;
        third_party_invite.membership.third_party_invite = true;

        WHEN("auth events are selected")
        {
            auto const normal_selection = merovingian::events::select_auth_events(normal_invite);
            auto const third_party_selection = merovingian::events::select_auth_events(third_party_invite);

            THEN("normal invite requires {create, power_levels, join_rules, member}")
            {
                // Spec MUST: create is always explicit in auth_events for v1–v11.
                // Do NOT remove create — an incomplete set causes remote auth failure.
                REQUIRE(normal_selection.required.size() == 4U);
                REQUIRE(normal_selection.required[0].kind == merovingian::events::AuthEventKind::create);
                REQUIRE(normal_selection.required[1].kind == merovingian::events::AuthEventKind::power_levels);
                REQUIRE(normal_selection.required[2].kind == merovingian::events::AuthEventKind::join_rules);
                REQUIRE(normal_selection.required[3].kind == merovingian::events::AuthEventKind::member);
                REQUIRE(normal_selection.required[3].state_key == "@bob:example.org");
            }

            THEN("3PID invite additionally requires m.room.third_party_invite")
            {
                // Spec MUST: 3PID invite adds third_party_invite on top of the base 4.
                REQUIRE(third_party_selection.required.size() == 5U);
                REQUIRE(third_party_selection.required[4].kind ==
                        merovingian::events::AuthEventKind::third_party_invite);
            }
        }
    }
}

// --- room version 12 (create event is implicit — derived from the room ID) ---
SCENARIO("Auth event selection omits m.room.create for room version 12",
         "[events][auth][auth-events][room-version][conformance]")
{
    GIVEN("a v12 m.room.member invite request")
    {
        auto normal_invite = merovingian::events::EventAuthorizationRequest{};
        normal_invite.room_version = "12";
        normal_invite.event_type = "m.room.member";
        normal_invite.state_key = "@bob:example.org";
        normal_invite.membership.requested_membership = merovingian::events::MembershipState::invite;

        auto third_party_invite = normal_invite;
        third_party_invite.membership.third_party_invite = true;

        WHEN("auth events are selected")
        {
            auto const normal_selection = merovingian::events::select_auth_events(normal_invite);
            auto const third_party_selection = merovingian::events::select_auth_events(third_party_invite);

            THEN("normal invite requires {power_levels, join_rules, member} — no create")
            {
                // Spec MUST: in v12 the create event is implicit in the room ID and
                // MUST NOT be listed in auth_events. Including it would be a protocol
                // violation — remote servers would reject the event.
                REQUIRE(normal_selection.required.size() == 3U);
                REQUIRE(normal_selection.required[0].kind == merovingian::events::AuthEventKind::power_levels);
                REQUIRE(normal_selection.required[1].kind == merovingian::events::AuthEventKind::join_rules);
                REQUIRE(normal_selection.required[2].kind == merovingian::events::AuthEventKind::member);
                REQUIRE(normal_selection.required[2].state_key == "@bob:example.org");
            }

            THEN("3PID invite additionally requires m.room.third_party_invite")
            {
                // Spec MUST: 3PID invite adds third_party_invite on top of the v12 base 3.
                REQUIRE(third_party_selection.required.size() == 4U);
                REQUIRE(third_party_selection.required[3].kind ==
                        merovingian::events::AuthEventKind::third_party_invite);
            }
        }
    }
}

// --- auth-chain deduplication -------------------------------------------------
// Spec: Matrix Server-Server API v1.19, auth_chain in send_join response
// URL:  ../../docs/matrix-v1.19-spec/server-server-api.md#put_matrixfederationv2send_joinroomideventid
//
// The auth chain is the transitive closure of auth_events across the room
// history. Duplicate event IDs and empty strings MUST NOT appear - they bloat
// send_join responses and may confuse remote servers' parsers.
SCENARIO("Auth-chain representation de-duplicates event IDs", "[events][auth][auth-chain]")
{
    GIVEN("an auth chain")
    {
        auto chain = merovingian::events::AuthChain{};

        WHEN("events are appended")
        {
            merovingian::events::append_auth_chain_event(chain, "$create");
            merovingian::events::append_auth_chain_event(chain, "$power");
            merovingian::events::append_auth_chain_event(chain, "$create"); // duplicate
            merovingian::events::append_auth_chain_event(chain, "");        // empty

            THEN("only unique non-empty event IDs are retained")
            {
                // Invariant: no duplicates, no empty strings in the auth chain.
                // Do NOT relax - duplicates in auth chains bloat send_join responses
                // and may cause remote servers to reject them.
                REQUIRE(chain.event_ids.size() == 2U);
                REQUIRE(merovingian::events::auth_chain_contains(chain, "$create"));
                REQUIRE(merovingian::events::auth_chain_contains(chain, "$power"));
                REQUIRE_FALSE(merovingian::events::auth_chain_contains(chain, "$missing"));
            }
        }
    }
}
