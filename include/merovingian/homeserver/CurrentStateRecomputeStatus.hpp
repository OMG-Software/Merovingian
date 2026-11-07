// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStore.hpp"

#include <cstdint>

namespace merovingian::homeserver
{

// How a recomputation of the room's current state ended (F-49, ADR-0375).
enum class CurrentStateRecomputeStatus : std::uint8_t
{
    // Current state is the resolution of the room's forward extremities: it was written where it
    // differed, or the room has no extremity to resolve.
    resolved,
    // The extremities could not be resolved (an extremity with no readable state, more extremities
    // than `max_state_groups`, the state budget, a missing auth-chain event, or a resolution that
    // fails closed). Current state was not touched, so it is NOT the resolution of the extremities:
    // each accepted event has put only its own row in it since. Logged at warning level.
    refused,
    // A diffed entry could not be written.
    write_failed,
};

} // namespace merovingian::homeserver
