// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/HomeserverRuntime.hpp"

#include <cstddef>
#include <string_view>

namespace merovingian::homeserver
{

// MSC4354, ADR-0856: queues to `destination` alone every unexpired sticky event in `room_id` that a user of this server
// sent, as the stored PDU unchanged, one transaction each in one batch, ordered by (expiry, event ID) (the order of
// `StickyEventTable::unexpired_of_room`), and returns how many the dispatch worker accepted. Another server's sticky
// events are never sent. Sends nothing when `ClientApiLimits::sticky_events_enabled` is false, when there is no dispatch
// worker, when `destination` is empty or this server, when the operator's federation policy refuses it, or when the
// room's `m.room.server_acl` denies it. Called where a remote server newly joins a room (the callers that send the
// joiner our device lists), never for a server already in the room. Only enqueues. The caller holds `runtime.mutex` (and,
// on the inbound path, the room's stripe); it takes no lock of its own.
auto push_local_sticky_events_to_server(HomeserverRuntime& runtime, std::string_view room_id,
                                        std::string_view destination) -> std::size_t;

} // namespace merovingian::homeserver
