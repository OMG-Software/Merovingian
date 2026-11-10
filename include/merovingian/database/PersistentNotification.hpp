// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::database
{

// A recorded notification for `GET /_matrix/client/v3/notifications` (Matrix
// v1.19 CS API §push-notifications). Recorded once per (user_id, event_id)
// whenever push rule evaluation resolves `notify: true` for that recipient --
// independent of whether the recipient has a registered pusher or whether
// `server.push.enabled` is set (a user with push notifications turned off
// must still see their notification history when they open the client; see
// RoomService.cpp's build_pending_push_deliveries). `actions` is the
// canonical-JSON-serialized actions array the matched rule produced;
// `highlight` mirrors its `set_tweak: highlight` action so `GET
// /notifications?only=highlight` can filter without re-parsing `actions`.
// `stream_ordering` is the triggering event's global stream position --
// unique per (user_id, event_id) row, since a recipient gets at most one
// notification per event -- and doubles as this table's pagination key,
// exactly like `events.stream_ordering` already does for GET /messages.
struct PersistentNotification final
{
    std::string user_id{};
    std::string room_id{};
    std::string event_id{};
    std::uint64_t stream_ordering{0U};
    std::uint64_t ts{0U};
    std::string actions{};
    std::string profile_tag{};
    bool highlight{false};
};

} // namespace merovingian::database
