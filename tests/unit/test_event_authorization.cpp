// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/events/authorization.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

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
                REQUIRE(decision.allowed);
                REQUIRE(decision.rule_hook == "auth_rules.room_v6_plus");
            }
        }
    }
}

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
        request.power_level = {49, 50};

        WHEN("the event is authorized")
        {
            auto const decision = merovingian::events::authorize_event(*room_v12, request);

            THEN("the event fails closed")
            {
                REQUIRE_FALSE(decision.allowed);
                REQUIRE(decision.reason == "insufficient power level");
            }
        }
    }
}

SCENARIO("Membership policy primitives cover joins, invites, removals, and restricted targets", "[events][auth][membership]")
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
            auto const unauthorized_remove_decision = merovingian::events::membership_policy_allows(unauthorized_remove);
            auto const authorized_remove_decision = merovingian::events::membership_policy_allows(authorized_remove);
            auto const restricted_decision = merovingian::events::membership_policy_allows(restricted);

            THEN("allowed transitions pass and unsafe transitions fail closed")
            {
                REQUIRE(self_join_decision.allowed);
                REQUIRE(invite_decision.allowed);
                REQUIRE_FALSE(unauthorized_remove_decision.allowed);
                REQUIRE(unauthorized_remove_decision.reason == "insufficient power to remove another member");
                REQUIRE(authorized_remove_decision.allowed);
                REQUIRE_FALSE(restricted_decision.allowed);
                REQUIRE(restricted_decision.reason == "target membership is restricted");
            }
        }
    }
}

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
                REQUIRE(normal_selection.required.size() == 4U);
                REQUIRE(normal_selection.required[0].kind == merovingian::events::AuthEventKind::create);
                REQUIRE(normal_selection.required[1].kind == merovingian::events::AuthEventKind::power_levels);
                REQUIRE(normal_selection.required[2].kind == merovingian::events::AuthEventKind::join_rules);
                REQUIRE(normal_selection.required[3].kind == merovingian::events::AuthEventKind::member);
                REQUIRE(normal_selection.required[3].state_key == "@bob:example.org");
                REQUIRE(third_party_selection.required.size() == 5U);
                REQUIRE(third_party_selection.required[4].kind == merovingian::events::AuthEventKind::third_party_invite);
            }
        }
    }
}

SCENARIO("Auth-chain representation de-duplicates event IDs", "[events][auth][auth-chain]")
{
    GIVEN("an auth chain")
    {
        auto chain = merovingian::events::AuthChain{};

        WHEN("events are appended")
        {
            merovingian::events::append_auth_chain_event(chain, "$create");
            merovingian::events::append_auth_chain_event(chain, "$power");
            merovingian::events::append_auth_chain_event(chain, "$create");
            merovingian::events::append_auth_chain_event(chain, "");

            THEN("only unique non-empty event IDs are retained")
            {
                REQUIRE(chain.event_ids.size() == 2U);
                REQUIRE(merovingian::events::auth_chain_contains(chain, "$create"));
                REQUIRE(merovingian::events::auth_chain_contains(chain, "$power"));
                REQUIRE_FALSE(merovingian::events::auth_chain_contains(chain, "$missing"));
            }
        }
    }
}
