// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <cstdint>
#include <optional>
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
    knock,
    restricted,
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
    // The event ID is stored separately from the signed PDU JSON. Callers that
    // build this map from persistent state must preserve the authoritative ID
    // for the create event so first-join authorization can verify prev_events.
    std::string create_event_id{};
    canonicaljson::Value power_levels{};
    canonicaljson::Value join_rules{};
    canonicaljson::Value sender_member{};
    canonicaljson::Value target_member{};
    canonicaljson::Value authorising_user_member{};
    canonicaljson::Value third_party_invite{};
};

[[nodiscard]] auto membership_name(MembershipState membership) noexcept -> char const*;
[[nodiscard]] auto authorize_event_against_auth_events(canonicaljson::Value const& event,
                                                       rooms::RoomVersionPolicy const& policy,
                                                       AuthEventMap const& auth_events) -> EventAuthorizationDecision;

[[nodiscard]] auto parse_membership_state(std::string_view membership) noexcept -> std::optional<MembershipState>;
// `allow_string_values` reflects RoomVersionPolicy::power_levels_require_integers
// inverted: room versions 1-9 permit an integer power level to be encoded as a
// string, and such an event is valid. Reading it as absent would silently apply
// a default instead of the level the room actually set, so the flag must follow
// the room's own version rather than defaulting per call site. It defaults to
// false (strict) so a caller that has not considered the question gets the v10+
// behaviour rather than the more permissive one.
[[nodiscard]] auto extract_user_power_level(canonicaljson::Value const& power_levels_event, std::string_view user_id,
                                            bool allow_string_values = false) noexcept -> std::int64_t;
// A sender's effective power level for auth-rule purposes: MSC4289 room
// creators (per `policy.privilege_room_creators`) get an effectively
// infinite level regardless of `power_levels`; otherwise the level comes
// from `power_levels` when present, or the pre-v12 default (the room's
// `content.creator` gets 100, everyone else 0) when it is absent.
[[nodiscard]] auto effective_sender_power(canonicaljson::Value const& power_levels, std::string_view sender,
                                          canonicaljson::Value const& create_event,
                                          rooms::RoomVersionPolicy const& policy) noexcept -> std::int64_t;
[[nodiscard]] auto extract_power_level_key(canonicaljson::Value const& power_levels_event, std::string_view key,
                                           std::int64_t default_value,
                                           bool allow_string_values = false) noexcept -> std::int64_t;
[[nodiscard]] auto domain_of(std::string_view matrix_id) noexcept -> std::string_view;
[[nodiscard]] auto extract_content_membership(canonicaljson::Value const& event) noexcept -> std::string;

} // namespace merovingian::events
