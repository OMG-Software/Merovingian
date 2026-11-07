// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/events/state_resolution.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <string>
#include <vector>

namespace merovingian::homeserver
{

// What a new local event is built on: the prev_events it declares and the
// state before it, resolved once, before the event is signed.
struct NewEventBasis final
{
    // False when no forward extremity has a state this server can compute;
    // the event must not be stored. `reason` says why.
    bool ok{false};
    std::vector<std::string> prev_event_ids{};
    std::vector<database::PersistentStateGroupStateEntry> state_before{};
    // Forward extremities the event does not cite because the state across
    // them could not be resolved. Storing the event removes them from the
    // room's extremities along with `prev_event_ids` (ADR-0225).
    std::vector<std::string> retired_extremities{};
    std::string reason{};
};

} // namespace merovingian::homeserver
