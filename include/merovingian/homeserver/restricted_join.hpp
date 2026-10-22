// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

// How this server, resident in a room, answers a join by a user who is not yet
// a member (audit R04, ADR-0185).
//
// client-server-api.md "Restricted rooms": "When joining without an invite,
// the server MUST verify that the requesting user meets at least one of the
// conditions." server-server-api.md "Restricted rooms" names the refusals:
// 400 M_UNABLE_TO_AUTHORISE_JOIN when no condition can be validated, 400
// M_UNABLE_TO_GRANT_JOIN when a condition holds but no user of this server can
// meet the auth rules for join_authorised_via_users_server, and 403 M_FORBIDDEN
// when the user fails every condition.
enum class RestrictedJoinVerdict : std::uint8_t
{
    // The room's join rule is not restricted or knock_restricted under its
    // room version: join_authorised_via_users_server plays no part.
    not_restricted,
    // The user is invited or already joined: "If the user has an invite to the
    // room then the restrictions will not affect them."
    already_permitted,
    // A condition holds and `authorising_user` (a joined user of this server
    // with at least the invite power level) may authorise the join.
    authorised,
    unable_to_authorise,
    unable_to_grant,
    forbidden,
};

struct RestrictedJoinDecision final
{
    RestrictedJoinVerdict verdict{RestrictedJoinVerdict::forbidden};
    // Set when `verdict` is `authorised`: the user ID to put in
    // content.join_authorised_via_users_server and the ID of that user's
    // current m.room.member event, which auth events selection names for the
    // join (server-server-api.md "Auth events selection").
    std::string authorising_user{};
    std::string authorising_member_event_id{};
    std::string reason{};
};

// The number of allow conditions in m.room.join_rules that are considered.
// The list is room state another server's administrator can write, and each
// condition costs a lookup in this server's state under runtime.mutex, so it
// is bounded; a condition past the bound is treated as absent (fail closed).
// ADR-0185.
inline constexpr std::size_t max_restricted_join_conditions{32U};

// Decides a join of `user_id` into `room_id` from this server's current state
// (`our_server` is this server's name). `named_authoriser`, when not empty, is
// the join_authorised_via_users_server a submitted join already names (the
// send_join path): only that user is considered, and it must be a user of
// this server. When empty (make_join, or a local join) the authorising user is
// chosen: the lowest user ID among this server's joined users with the invite
// power level. A condition's room can be validated only while this server is
// resident in it (its m.room.create is stored and a user of this server is
// joined): state kept after leaving is not current. No condition met and one
// that cannot be validated is unable_to_authorise; all validated and none met
// is forbidden. Reads only; the caller holds runtime.mutex.
[[nodiscard]] auto decide_restricted_join(database::PersistentStore const& store, std::string_view room_id,
                                          std::string_view user_id, std::string_view our_server,
                                          std::string_view named_authoriser = {}) -> RestrictedJoinDecision;

// The HTTP status and Matrix errcode for a refusing verdict
// (unable_to_authorise, unable_to_grant, forbidden). Any other verdict is not
// a refusal and maps to 200 / an empty errcode.
[[nodiscard]] auto restricted_join_refusal_status(RestrictedJoinVerdict verdict) noexcept -> std::uint16_t;
[[nodiscard]] auto restricted_join_refusal_errcode(RestrictedJoinVerdict verdict) noexcept -> std::string_view;

} // namespace merovingian::homeserver
