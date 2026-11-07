// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/sync/RoomListResult.hpp"
#include "merovingian/sync/SlidingSyncList.hpp"
#include "merovingian/sync/SlidingSyncOp.hpp"
#include "merovingian/sync/unread_event_classifier.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::sync
{

// Compute the windowed room list, sort order, and ops for one named list.
//
// `prev_window` — the room IDs returned in the last response for this list
//   (from SlidingSyncConnectionState::list_prev_windows). Empty on the first
//   request for a given list.
[[nodiscard]] auto compute_room_list(homeserver::HomeserverRuntime const& rt, std::string_view user,
                                     SlidingSyncList const& list, std::vector<std::string> const& prev_window,
                                     database::PersistentStore const& store) -> RoomListResult;

// As above, with the request's one classifier of unread events (R15), which the
// `by_notification_count` sort counts with. The overload above builds its own.
[[nodiscard]] auto compute_room_list(homeserver::HomeserverRuntime const& rt, std::string_view user,
                                     SlidingSyncList const& list, std::vector<std::string> const& prev_window,
                                     database::PersistentStore const& store, UnreadEventClassifier& unread)
    -> RoomListResult;

} // namespace merovingian::sync
