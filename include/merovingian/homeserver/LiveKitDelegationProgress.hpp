// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::homeserver
{

// What the "livekit-delegations" job knows of one stored delegation (ADR-0832), keyed by its delay ID in
// `HomeserverRuntime::livekit_delegation_progress`. In memory only: after a restart every delegation starts again as
// never seen and due for a check. Guarded by `runtime.mutex`.
struct LiveKitDelegationProgress final
{
    // The delegation's MSC4195 LiveKit room name and participant identity, derived once from the stored row, so a
    // webhook is matched without hashing every delegation.
    std::string room_name{};
    std::string identity{};
    // When LiveKit last answered that the participant is connected (wall-clock ms); 0 = never.
    std::uint64_t last_seen_connected_ms{0U};
    // When the next GetParticipant check is due (wall-clock ms); 0 = at the next run.
    std::uint64_t next_check_ms{0U};
};

} // namespace merovingian::homeserver
