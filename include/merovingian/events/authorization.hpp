// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
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
// Why `content` is not a valid m.room.power_levels content for the room version
// (auth rule 9's shape checks: scalar levels, the events/notifications maps and
// users), or an empty string when it is. For a caller that must refuse content
// before building an event from it.
[[nodiscard]] auto power_levels_content_problem(canonicaljson::Object const& content,
                                                rooms::RoomVersionPolicy const& policy) -> std::string;
[[nodiscard]] auto authorize_event_against_auth_events(canonicaljson::Value const& event,
                                                       rooms::RoomVersionPolicy const& policy,
                                                       AuthEventMap const& auth_events) -> EventAuthorizationDecision;

// A join's content.join_authorised_via_users_server, or empty. Spec "Auth events selection": "If
// membership is join, content.join_authorised_via_users_server is present, and the room version
// supports restricted rooms, then the m.room.member event with state_key matching
// content.join_authorised_via_users_server". No room-version gate here, as in state resolution: only
// the restricted join branch reads the member event, and no pre-v8 room reaches it.
[[nodiscard]] auto join_authorising_user(canonicaljson::Value const& event) -> std::string;
// An invite's content.third_party_invite.signed.token, or empty.
[[nodiscard]] auto third_party_invite_token(canonicaljson::Value const& event) -> std::string;
// The (type, state_key) pairs an event's auth_events MAY name, per spec "Auth events selection"
// (server-server-api.md).
[[nodiscard]] auto permitted_auth_event_keys(canonicaljson::Value const& pdu, rooms::RoomVersionPolicy const& policy,
                                             std::string_view event_type, std::string_view sender,
                                             std::optional<std::string> const& state_key,
                                             std::string_view third_party_invite_token)
    -> std::vector<std::pair<std::string, std::string>>;

// What decides which slots of an AuthEventMap a state event fills, for the event being judged.
struct AuthEventSlots final
{
    std::string_view sender{};
    std::string_view target_state_key{};
    std::string_view event_type{};
    std::string_view third_party_invite_token{};
    // A join's content.join_authorised_via_users_server (join_authorising_user). The authorising
    // server's signature is verified before any of this, on every ingestion path (ADR-0171); the
    // map only lets the membership and power checks run.
    std::string_view authorising_user{};
};

// Puts one state event into the slots of `map` it fills. `load` returns the event's JSON and is called
// only for an event that fills a slot, so a caller that must parse it pays nothing for the others.
template <typename LoadEvent>
auto fill_auth_event_slot(AuthEventMap& map, AuthEventSlots const& slots, std::string_view type,
                          std::string_view state_key, std::string_view event_id, LoadEvent const& load) -> void
{
    if (type == "m.room.create" && state_key.empty())
    {
        map.create = load(event_id);
        map.create_event_id = std::string{event_id};
    }
    else if (type == "m.room.power_levels" && state_key.empty())
    {
        map.power_levels = load(event_id);
    }
    else if (type == "m.room.join_rules" && state_key.empty())
    {
        map.join_rules = load(event_id);
    }
    else if (type == "m.room.member" && state_key == slots.sender)
    {
        map.sender_member = load(event_id);
    }
    else if (type == "m.room.member" && slots.event_type == "m.room.member" && state_key == slots.target_state_key)
    {
        map.target_member = load(event_id);
    }
    else if (type == "m.room.third_party_invite" && !slots.third_party_invite_token.empty() &&
             state_key == slots.third_party_invite_token)
    {
        map.third_party_invite = load(event_id);
    }
    // Not part of the chain above: the authorising user may also be the sender or target, and each
    // slot must still be filled.
    if (!slots.authorising_user.empty() && type == "m.room.member" && state_key == slots.authorising_user)
    {
        map.authorising_user_member = load(event_id);
    }
}

[[nodiscard]] auto parse_membership_state(std::string_view membership) noexcept -> std::optional<MembershipState>;
// The forms a power level may take in a room version. Room versions 1-9 permit
// an integer encoded as a string (rooms/v10.md removed it), and 1-5 also permit a
// float, read by truncation (rooms/v3.md; v6 enforces Canonical JSON). Such
// events are valid: reading a value as absent would silently apply a default
// instead of the level the room actually set, so the encoding must follow the
// room's own version (power_level_encoding) rather than be chosen per call
// site. The parameters default to `integers` (strict) so a caller that has not
// considered the question gets the v10+ behaviour, not a more permissive one.
enum class PowerLevelEncoding : std::uint8_t
{
    integers,
    integers_or_strings,
    integers_strings_or_floats,
};
[[nodiscard]] auto power_level_encoding(rooms::RoomVersionPolicy const& policy) noexcept -> PowerLevelEncoding;
// One power-level value (a top-level level, or an entry of `events`, `notifications` or `users`)
// read as the authorization rules read it in `encoding`: an integer; under the legacy encodings
// also an integer written as a string, or (v1-5) a float truncated at the decimal point. nullopt
// when it is not a level in a form `encoding` accepts, which the rules treat as invalid. A caller
// that reads levels outside the auth rules uses this rather than its own parsing.
[[nodiscard]] auto decode_power_level(canonicaljson::Value const& value, PowerLevelEncoding encoding) noexcept
    -> std::optional<std::int64_t>;
[[nodiscard]] auto extract_user_power_level(canonicaljson::Value const& power_levels_event, std::string_view user_id,
                                            PowerLevelEncoding encoding = PowerLevelEncoding::integers) noexcept
    -> std::int64_t;
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
                                           PowerLevelEncoding encoding = PowerLevelEncoding::integers) noexcept
    -> std::int64_t;
// The power level a state event of `event_type` requires under `power_levels_event`
// (a full event value, or null when the room has none): `events[event_type]` when
// listed, else `state_default`, else 50. The authorization rule for state events
// uses this, and so do the client API gates that refuse an action up front because
// the state event it would send would be rejected (CSAZ-12).
[[nodiscard]] auto required_state_event_power(canonicaljson::Value const& power_levels_event,
                                              std::string_view event_type,
                                              rooms::RoomVersionPolicy const& policy) noexcept -> std::int64_t;
[[nodiscard]] auto domain_of(std::string_view matrix_id) noexcept -> std::string_view;
[[nodiscard]] auto extract_content_membership(canonicaljson::Value const& event) noexcept -> std::string;

} // namespace merovingian::events
