// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/events/authorization.hpp>

#include <algorithm>
#include <string>

namespace merovingian::events
{
namespace
{

[[nodiscard]] auto auth_rule_name(rooms::AuthRules rules) noexcept -> char const*
{
    switch (rules)
    {
    case rooms::AuthRules::room_v1:
        return "room_v1";
    case rooms::AuthRules::room_v6_plus:
        return "room_v6_plus";
    }

    return "unknown";
}

[[nodiscard]] auto requires_power_levels(std::string_view event_type) noexcept -> bool
{
    return event_type != "m.room.create";
}

[[nodiscard]] auto requires_membership(std::string_view event_type) noexcept -> bool
{
    return event_type == "m.room.member";
}

} // namespace

auto auth_rule_hook_name(rooms::RoomVersionPolicy const& policy) -> std::string
{
    return std::string{"auth_rules."} + auth_rule_name(policy.auth_rules);
}

auto membership_name(MembershipState membership) noexcept -> char const*
{
    switch (membership)
    {
    case MembershipState::leave:
        return "leave";
    case MembershipState::invite:
        return "invite";
    case MembershipState::join:
        return "join";
    case MembershipState::restricted:
        return "restricted";
    }

    return "unknown";
}

auto power_level_allows(PowerLevelPolicy policy) noexcept -> bool
{
    return policy.sender_power >= policy.required_power;
}

auto membership_policy_allows(MembershipPolicy policy) -> EventAuthorizationDecision
{
    if (policy.target_is_restricted)
    {
        return {false, "membership", "target membership is restricted"};
    }
    if (policy.requested_membership == MembershipState::join && policy.target_is_sender)
    {
        return {true, "membership", {}};
    }
    if (policy.requested_membership == MembershipState::invite)
    {
        if (policy.sender_power >= policy.invite_power)
        {
            return {true, "membership", {}};
        }
        return {false, "membership", "insufficient power to invite"};
    }
    if (policy.requested_membership == MembershipState::restricted)
    {
        if (policy.sender_power >= policy.restrict_power)
        {
            return {true, "membership", {}};
        }
        return {false, "membership", "insufficient power to restrict membership"};
    }
    if (policy.requested_membership == MembershipState::leave)
    {
        if (policy.target_is_sender)
        {
            return {true, "membership", {}};
        }
        if (policy.sender_power >= policy.remove_power)
        {
            return {true, "membership", {}};
        }
        return {false, "membership", "insufficient power to remove another member"};
    }

    return {false, "membership", "membership transition is not allowed"};
}

auto authorize_event(rooms::RoomVersionPolicy const& policy, EventAuthorizationRequest const& request)
    -> EventAuthorizationDecision
{
    auto const rule_hook = auth_rule_hook_name(policy);
    if (policy.id != request.room_version)
    {
        return {false, rule_hook, "room version mismatch"};
    }
    if (request.event_type.empty())
    {
        return {false, rule_hook, "event type is required"};
    }
    if (!power_level_allows(request.power_level))
    {
        return {false, rule_hook, "insufficient power level"};
    }
    if (requires_membership(request.event_type))
    {
        auto membership_decision = membership_policy_allows(request.membership);
        membership_decision.rule_hook = rule_hook;
        return membership_decision;
    }

    return {true, rule_hook, {}};
}

auto select_auth_events(EventAuthorizationRequest const& request) -> AuthEventSelection
{
    auto selection = AuthEventSelection{};
    selection.required.push_back({AuthEventKind::create, "m.room.create", ""});

    if (requires_power_levels(request.event_type))
    {
        selection.required.push_back({AuthEventKind::power_levels, "m.room.power_levels", ""});
    }
    if (request.event_type == "m.room.member")
    {
        selection.required.push_back({AuthEventKind::join_rules, "m.room.join_rules", ""});
        selection.required.push_back({AuthEventKind::member, "m.room.member", request.state_key});
    }
    if (request.membership.third_party_invite)
    {
        selection.required.push_back({AuthEventKind::third_party_invite, "m.room.third_party_invite", request.state_key});
    }

    return selection;
}

auto auth_event_kind_name(AuthEventKind kind) noexcept -> char const*
{
    switch (kind)
    {
    case AuthEventKind::create:
        return "create";
    case AuthEventKind::power_levels:
        return "power_levels";
    case AuthEventKind::join_rules:
        return "join_rules";
    case AuthEventKind::member:
        return "member";
    case AuthEventKind::third_party_invite:
        return "third_party_invite";
    }

    return "unknown";
}

auto auth_chain_contains(AuthChain const& chain, std::string_view event_id) noexcept -> bool
{
    return std::ranges::any_of(chain.event_ids, [event_id](std::string const& existing) {
        return existing == event_id;
    });
}

auto append_auth_chain_event(AuthChain& chain, std::string_view event_id) -> void
{
    if (!event_id.empty() && !auth_chain_contains(chain, event_id))
    {
        chain.event_ids.push_back(std::string{event_id});
    }
}

} // namespace merovingian::events
