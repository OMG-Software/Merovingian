// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::federation
{

// Outcome of a room-scoped federation read (`/event`, `/state`, `/state_ids`,
// `/get_missing_events`). `forbidden` means the requesting server is not in the
// room and the room is not world readable (FED-2); the inbound handler answers
// it with 403 M_FORBIDDEN and no room data. `too_large` means the complete
// answer is longer than this server's bound for it (`/event_auth`, ADR-0284):
// no part of it is sent, since a part is not the complete answer.
enum class RoomReadStatus : unsigned char
{
    ok,
    forbidden,
    not_found,
    malformed,
    too_large,
};

} // namespace merovingian::federation
