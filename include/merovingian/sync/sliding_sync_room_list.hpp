// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/sync/sliding_sync.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::sync
{

// Result of computing one named room list for an MSC4186 sliding sync response.
struct RoomListResult final
{
    // Total number of rooms matching the list's filters (for list.count).
    std::uint64_t              count{0U};
    // Ordered room IDs covering the union of all requested ranges.
    std::vector<std::string>   windowed_room_ids{};
    // Ops to include in the list response.
    std::vector<SlidingSyncOp> ops{};
};

// Compute the windowed room list, sort order, and ops for one named list.
//
// `prev_window` — the room IDs returned in the last response for this list
//   (from SlidingSyncConnectionState::list_prev_windows). Empty on the first
//   request for a given list.
[[nodiscard]] auto compute_room_list(
    homeserver::HomeserverRuntime const& rt,
    std::string_view                     user,
    SlidingSyncList const&               list,
    std::vector<std::string> const&      prev_window,
    database::PersistentStore const&     store) -> RoomListResult;

} // namespace merovingian::sync
