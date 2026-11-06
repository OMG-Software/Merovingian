// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::homeserver
{

// Ephemeral data (m.typing, m.receipt, m.presence) waiting to ride the next transaction to one
// appservice that set `receive_ephemeral` (R08, ADR-0190). In memory only and bounded: ephemeral
// data describes the present, so a restart or an overflow loses nothing worth keeping, and
// persisting it would put one database write behind every typing indicator.
//
// `key` is what makes two items the same fact about the present (one room's typing list, one
// user's presence, one user's receipt of one type in one thread). A newer item with the same key
// replaces the older one, so a chatty room cannot fill the queue with states already superseded.
struct AppserviceEphemeralItem final
{
    std::string key{};
    std::string json{}; // one serialized client-format event, `room_id` included when room-scoped
};

} // namespace merovingian::homeserver
