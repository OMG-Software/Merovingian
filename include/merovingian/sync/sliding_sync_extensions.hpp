// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/sync/sliding_sync.hpp"

#include <cstdint>
#include <string_view>
#include <vector>

namespace merovingian::sync
{

// Build the five optional MSC4186 extension responses for one sliding sync tick.
//
// `since_sync_stream_id`   — client's last-known sync stream position (0 on first request).
// `current_sync_stream_id` — current top of the sync stream; used to derive
//                            the to_device next_batch opaque token.
// `response_room_ids`      — union of all room IDs appearing in the rooms map of the current
//                            response. Scopes receipts and typing when the extension request
//                            does not name explicit rooms.
//
// `store` is mutable because the to_device extension drains delivered messages via
// drain_to_device_messages, which removes them from the in-memory queue.
[[nodiscard]] auto build_extensions(
    homeserver::HomeserverRuntime const&    rt,
    std::string_view                        user,
    std::string_view                        device_id,
    SlidingSyncExtensionRequests const&     ext_req,
    std::uint64_t                           since_sync_stream_id,
    std::uint64_t                           current_sync_stream_id,
    database::PersistentStore&              store,
    std::vector<std::string> const&         response_room_ids) -> SlidingSyncExtensionResponses;

} // namespace merovingian::sync
