// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::events
{

enum class MembershipState
{
    leave,
    invite,
    join,
    ban,
    restricted,
};

struct PowerLevelPolicy final
{
    std::int64_t sender_power{0};
    std::int64_t required_power{0};
};

struct MembershipPolicy final
{
    MembershipState current_membership{MembershipState::leave};
    MembershipState requested_membership{MembershipState::join};
    bool target_is_sender{true};
    bool target_is_restricted{false};
    bool third_party_invite{false};
    std::int64_t sender_power{0};
    std::int64_t restrict_power{50};
    std::int64_t invite_power{0};
    std::int64_t remove_power{50};
};

struct EventAuthorizationRequest final
{
    std::string room_version{};
    std::string event_type{};
    std::string state_key{};
    std::string sender{};
    PowerLevelPolicy power_level{};
    MembershipPolicy membership{};
};

struct EventAuthorizationDecision final
{
    bool allowed{false};
    std::string rule_hook{};
    std::string rule_step{};
    std::string reason{};
};

struct AuthEventMap final
{
    canonicaljson::Value create{};
    canonicaljson::Value power_levels{};
    canonicaljson::Value join_rules{};
    canonicaljson::Value sender_member{};
    canonicaljson::Value target_member{};
    canonicaljson::Value third_party_invite{};
};

enum class AuthEventKind
{
    create,
    power_levels,
    join_rules,
    member,
    third_party_invite,
};

struct AuthEventReference final
{
    AuthEventKind kind{AuthEventKind::create};
    std::string event_type{};
    std::string state_key{};
};

struct AuthEventSelection final
{
    std::vector<AuthEventReference> required{};
};

struct AuthChain final
{
    std::vector<std::string> event_ids{};
};

[[nodiscard]] auto auth_rule_hook_name(rooms::RoomVersionPolicy const& policy) -> std::string;
[[nodiscard]] auto membership_name(MembershipState membership) noexcept -> char const*;
[[nodiscard]] auto power_level_allows(PowerLevelPolicy policy) noexcept -> bool;
[[nodiscard]] auto membership_policy_allows(MembershipPolicy policy) -> EventAuthorizationDecision;
[[nodiscard]] auto authorize_event(rooms::RoomVersionPolicy const& policy, EventAuthorizationRequest const& request)
    -> EventAuthorizationDecision;
[[nodiscard]] auto authorize_event_against_auth_events(canonicaljson::Value const& event,
                                                       rooms::RoomVersionPolicy const& policy,
                                                       AuthEventMap const& auth_events) -> EventAuthorizationDecision;
[[nodiscard]] auto select_auth_events(EventAuthorizationRequest const& request) -> AuthEventSelection;
[[nodiscard]] auto auth_event_kind_name(AuthEventKind kind) noexcept -> char const*;
[[nodiscard]] auto auth_chain_contains(AuthChain const& chain, std::string_view event_id) noexcept -> bool;
auto append_auth_chain_event(AuthChain& chain, std::string_view event_id) -> void;

[[nodiscard]] auto parse_membership_state(std::string_view membership) noexcept -> MembershipState;
[[nodiscard]] auto extract_user_power_level(canonicaljson::Value const& power_levels_event,
                                            std::string_view user_id) noexcept -> std::int64_t;
[[nodiscard]] auto extract_power_level_key(canonicaljson::Value const& power_levels_event, std::string_view key,
                                           std::int64_t default_value) noexcept -> std::int64_t;
[[nodiscard]] auto domain_of(std::string_view matrix_id) noexcept -> std::string_view;
[[nodiscard]] auto extract_content_membership(canonicaljson::Value const& event) noexcept -> std::string;

} // namespace merovingian::events
