// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/events/state_resolution.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <string>

namespace merovingian::homeserver
{

// Whether store_event_with_bookkeeping stored the event, and if not, the step
// that refused it (`event`, `state_group`, `current_state` or `commit`) and why.
struct StoredWithBookkeeping final
{
    bool ok{false};
    std::string step{};
    std::string reason{};
    // True when the event was stored but the room's forward extremities could not be resolved
    // (F-49), so current state holds only the event's own row beyond what it already held. A
    // warning was logged. `resolution_refusal` says why.
    bool resolution_refused{false};
    std::string resolution_refusal{};
};

} // namespace merovingian::homeserver
