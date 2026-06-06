// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX EVENT AUTHORIZATION CONFORMANCE TESTS                    |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.18, Room Version 6+ auth rules       |
// |  URL:  https://spec.matrix.org/v1.18/rooms/v6/#authorization-rules      |
// |        https://spec.matrix.org/v1.18/server-server-api/#auth-rules      |
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

// --- auth-rule hook dispatch --------------------------------------------------
// Spec: Matrix Room Version 6, Sec. 10.4 Authorization rules
// URL:  https://spec.matrix.org/v1.18/rooms/v6/#authorization-rules
//
// Room versions v6 and later share the same authorization rule set.
// The implementation MUST dispatch to the correct versioned rule hook rather
// than hard-coding a single rule set, to remain correct as room versions evolve.
SCENARIO("Event authorization uses room-version-specific auth-rule hooks", "[events][auth]")
{
    GIVEN("a modern room version policy and authorization request")
    {
        auto const* room_v12 = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(room_v12 != nullptr);
        auto request = merovingian::events::EventAuthorizationRequest{};
        request.room_version = "12";
        request.event_type = "m.room.message";
        request.sender = "@alice:example.org";
        request.power_level = {50, 0};

        WHEN("the event is authorized")
        {
            auto const decision = merovingian::events::authorize_event(*room_v12, request);

            THEN("the room-version auth hook is reported")
            {
                // Spec: room v6+ share the auth_rules.room_v6_plus rule set.
                // Do NOT change the hook name - it identifies which auth rules
                // were applied and appears in audit trails.
                REQUIRE(decision.allowed);
                REQUIRE(decision.rule_hook == "auth_rules.room_v6_plus");
            }
        }
    }
}

// --- power level enforcement --------------------------------------------------
// Spec: Matrix Room Version 6, Sec. 10.4.6 Auth rule: power levels
// URL:  https://spec.matrix.org/v1.18/rooms/v6/#authorization-rules
//
// "The sender's current power level in the room MUST be greater than or equal
// to the level required to send that event type." A server MUST reject events
// where the sender's power level is below the required threshold.
SCENARIO("Event authorization rejects insufficient power levels", "[events][auth][power-levels]")
{
    GIVEN("a power-level protected event")
    {
        auto const* room_v12 = merovingian::rooms::find_room_version_policy("12");
        REQUIRE(room_v12 != nullptr);
        auto request = merovingian::events::EventAuthorizationRequest{};
        request.room_version = "12";
        request.event_type = "m.room.power_levels";
        request.sender = "@alice:example.org";
        request.power_level = {49, 50}; // sender_power=49 < required=50

        WHEN("the event is authorized")
        {
            auto const decision = merovingian::events::authorize_event(*room_v12, request);

            THEN("the event fails closed")
            {
                // Spec MUST: reject when sender power < required power.
                // Do NOT change to allowed - this is a hard security gate.
                // A regression here permits privilege escalation in the room.
                REQUIRE_FALSE(decision.allowed);
                REQUIRE(decision.reason == "insufficient power level");
            }
        }
    }
}

// --- membership policy --------------------------------------------------------
// Spec: Matrix Room Version 6, Sec. 10.4.3 Auth rules for m.room.member
// URL:  https://spec.matrix.org/v1.18/rooms/v6/#authorization-rules
//
// Self-joins and invites by sufficiently powerful members MUST be allowed.
// Kicks (forced leave on a third party) by members with insufficient power
// MUST be rejected. Restricted membership targets MUST be rejected.
SCENARIO("Membership policy primitives cover joins, invites, removals, and restricted targets",
         "[events][auth][membership]")
{
    GIVEN("membership policy decisions")
    {
        auto self_join = merovingian::events::MembershipPolicy{};
        self_join.requested_membership = merovingian::events::MembershipState::join;
        self_join.target_is_sender = true;

        auto invite = merovingian::events::MembershipPolicy{};
        invite.requested_membership = merovingian::events::MembershipState::invite;
        invite.target_is_sender = false;
        invite.sender_power = 50;
        invite.invite_power = 50;

        auto unauthorized_remove = merovingian::events::MembershipPolicy{};
        unauthorized_remove.current_membership = merovingian::events::MembershipState::join;
        unauthorized_remove.requested_membership = merovingian::events::MembershipState::leave;
        unauthorized_remove.target_is_sender = false;
        unauthorized_remove.sender_power = 0;
        unauthorized_remove.remove_power = 50;

        auto authorized_remove = unauthorized_remove;
        authorized_remove.sender_power = 50;

        auto restricted = merovingian::events::MembershipPolicy{};
        restricted.target_is_restricted = true;

        WHEN("membership policy is evaluated")
        {
            auto const self_join_decision = merovingian::events::membership_policy_allows(self_join);
            auto const invite_decision = merovingian::events::membership_policy_allows(invite);
            auto const unauthorized_remove_decision =
                merovingian::events::membership_policy_allows(unauthorized_remove);
            auto const authorized_remove_decision = merovingian::events::membership_policy_allows(authorized_remove);
            auto const restricted_decision = merovingian::events::membership_policy_allows(restricted);

            THEN("allowed transitions pass and unsafe transitions fail closed")
            {
                // Spec MUST: a user may join a room they are not already in.
                REQUIRE(self_join_decision.allowed);
                // Spec MUST: a member with sufficient power may invite.
                REQUIRE(invite_decision.allowed);
                // Spec MUST: reject kicks by members with insufficient power.
                // Do NOT relax - this prevents unprivileged members from removing others.
                REQUIRE_FALSE(unauthorized_remove_decision.allowed);
                REQUIRE(unauthorized_remove_decision.reason == "insufficient power to remove another member");
                // Spec MUST: allow kicks by members with sufficient power.
                REQUIRE(authorized_remove_decision.allowed);
                // Spec MUST: reject restricted membership targets.
                REQUIRE_FALSE(restricted_decision.allowed);
                REQUIRE(restricted_decision.reason == "target membership is restricted");
            }
        }
    }
}

// --- auth event selection -----------------------------------------------------
// Spec: Matrix Server-Server API v1.18 Sec. 4.4 auth_events
// URL:  https://spec.matrix.org/v1.18/server-server-api/#auth-events
//
// For m.room.member invite the REQUIRED auth event set is:
//   {m.room.create, m.room.power_levels, m.room.join_rules, m.room.member(target)}
// Third-party invites additionally require m.room.third_party_invite.
// A wrong or incomplete auth_events set causes remote auth failure.
SCENARIO("Auth event selection registers required auth events for membership events", "[events][auth][auth-events]")
{
    GIVEN("membership authorization requests")
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

            THEN("normal invites avoid 3PID auth and third-party invites request it")
            {
                // Spec MUST: exactly 4 auth events for a normal invite.
                // Do NOT change the size or order - auth event sets are normative.
                // An incomplete set causes the event to fail auth on remote servers.
                REQUIRE(normal_selection.required.size() == 4U);
                REQUIRE(normal_selection.required[0].kind == merovingian::events::AuthEventKind::create);
                REQUIRE(normal_selection.required[1].kind == merovingian::events::AuthEventKind::power_levels);
                REQUIRE(normal_selection.required[2].kind == merovingian::events::AuthEventKind::join_rules);
                REQUIRE(normal_selection.required[3].kind == merovingian::events::AuthEventKind::member);
                REQUIRE(normal_selection.required[3].state_key == "@bob:example.org");
                // Spec MUST: 3PID invite additionally requires m.room.third_party_invite.
                REQUIRE(third_party_selection.required.size() == 5U);
                REQUIRE(third_party_selection.required[4].kind ==
                        merovingian::events::AuthEventKind::third_party_invite);
            }
        }
    }
}

// --- auth-chain deduplication -------------------------------------------------
// Spec: Matrix Server-Server API v1.18, auth_chain in send_join response
// URL:  https://spec.matrix.org/v1.18/server-server-api/#put_matrixfederationv2send_joinroomideventid
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
