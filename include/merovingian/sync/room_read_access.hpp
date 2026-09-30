// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::sync
{

// How much of a room's state a user may read.
enum class RoomReadKind
{
    // Never joined (invite, knock, a declined invite, no membership at all), or forgotten.
    none,
    // Joined now: the room's current state.
    current,
    // Was joined and has since left, been kicked or banned: the state as of the event that
    // ended the join.
    as_of,
};

struct RoomReadAccess final
{
    RoomReadKind kind{RoomReadKind::none};
    // `as_of` only: the `m.room.member` event that ended the user's most recent join, and its
    // stream ordering.
    std::string boundary_event_id{};
    std::uint64_t boundary_ordering{0U};
};

// The one predicate behind `initialSync`, `/members`, `/state` and `/state/{type}/{key}`.
//
// Spec (client-server-api.md): `/members` "If you are joined to the room then this will be the
// current members of the room. If you have left the room then this will be the members of the
// room when you left." `403`: "You aren't a member of the room and weren't previously a
// member of the room." Room History Visibility: "After a user has left a room, they may see any
// events which they were allowed to see before they left the room, but no events received after
// they left."
//
// The current membership is the membership projection row, or, when the row has been forgotten
// (`/forget`) or is absent, the current `m.room.member` state event, which only ever grants
// `current` (a forgotten room grants nothing). A user whose current membership is leave or ban
// gets `as_of` only when the chain of their `m.room.member` events (`state_transitions`) shows
// a join before it, so a declined invite or a knock that was withdrawn is `none`. Every doubt
// (a broken chain, an inconsistent projection) is `none`.
[[nodiscard]] auto room_read_access_for(database::PersistentStore const& store, std::string_view room_id,
                                        std::string_view user_id) -> RoomReadAccess;

// The IDs of the state events `access` entitles the user to read, or nullopt when `access` is
// `none` or the state cannot be determined (fail closed).
//
// `current` without `at` is the room's current state. Otherwise the state is the one recorded
// (ADR-0064 state group) for the newest accepted event whose stream ordering is at or before
// `at`, and for `as_of` never later than the boundary event, so a departed user's `at` is
// capped at their leave.
[[nodiscard]] auto room_state_event_ids(database::PersistentStore const& store, std::string_view room_id,
                                        RoomReadAccess const& access,
                                        std::optional<std::uint64_t> at) -> std::optional<std::vector<std::string>>;

} // namespace merovingian::sync
