// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>

namespace merovingian::database
{

// The caps `record_sticky_event` keeps the unexpired sticky rows under (ADR-0854, ADR-0857). In production both come
// from `server.sticky_events` (`max_per_sender`, `max_per_room`); a cap of 0 refuses every row.
struct StickyEventCaps final
{
    // Unexpired rows one sender may hold across all rooms; one more expires the sender's oldest.
    std::size_t max_per_sender{60U};
    // Unexpired rows one room may hold, all senders together; one more expires the oldest row of the server that holds
    // the most rows in the room.
    std::size_t max_per_room{1000U};
};

} // namespace merovingian::database
