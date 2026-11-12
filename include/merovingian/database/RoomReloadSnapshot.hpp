// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentEvent.hpp"
#include "merovingian/database/PersistentEventStateGroup.hpp"
#include "merovingian/database/PersistentForwardExtremity.hpp"
#include "merovingian/database/PersistentInvite.hpp"
#include "merovingian/database/PersistentMembership.hpp"
#include "merovingian/database/PersistentRoom.hpp"
#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/PersistentStateGroup.hpp"
#include "merovingian/database/PersistentStateGroupStateEntry.hpp"

#include <optional>
#include <string>
#include <vector>

namespace merovingian::database
{

// Freshly-read rows for a single room, scoped by room_id, used by reload_room
// to refresh one room's slice of a PersistentStore without re-reading the
// entire database. `room` is nullopt when the room no longer exists in the
// backing database (e.g. it was never local to this server after all); the
// other fields are empty in that case. `events` carries prev_event_ids,
// auth_event_ids, and signatures already reconstructed from the flat
// relation tables — see reconstruct_event_relations.
struct RoomReloadSnapshot final
{
    // The room the rows belong to; load_room_snapshot sets it.
    std::string room_id{};
    std::optional<PersistentRoom> room{};
    std::vector<PersistentMembership> memberships{};
    std::vector<PersistentInvite> invites{};
    std::vector<PersistentEvent> events{};
    std::vector<PersistentStateEvent> state{};
    // The room's state groups (ADR-0064), their own entries, and the event -> group mapping of the
    // room's events, read in the same transaction as the rest. Federation reads judge an event on
    // its recorded group and fail closed without one, so a reload that left these behind made every
    // event created after the worker started look invisible.
    std::vector<PersistentStateGroup> state_groups{};
    std::vector<PersistentStateGroupStateEntry> state_group_state{};
    std::vector<PersistentEventStateGroup> event_state_groups{};
    // The room's forward extremities, read in the same transaction (ADR-0733): a federation worker builds its whole
    // store from these snapshots, and its make_leave and make_knock templates build on the tips.
    std::vector<PersistentForwardExtremity> forward_extremities{};
    // A memory-backed store has no database to read: nothing to apply (apply_room_snapshot returns at once).
    bool nothing_to_apply{false};
};

} // namespace merovingian::database
