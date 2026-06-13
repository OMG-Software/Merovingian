// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"

#include <string>
#include <string_view>

namespace merovingian::federation
{

// Builds the canonical-JSON response body for an inbound federation
// `GET /_matrix/federation/v1/event/{eventId}` request. Returns an empty
// string when the requested event is not in the store.
[[nodiscard]] auto build_event_response(database::PersistentStore const& store, std::string_view event_id,
                                        std::string_view origin_server_name) -> std::string;

// Builds the canonical-JSON response body for an inbound federation
// `GET /_matrix/federation/v1/state/{roomId}?event_id=...` request. Returns
// the room's current state events; historical-state-at-event reconstruction
// is not yet implemented. Returns an empty string when the room has no
// recorded state.
[[nodiscard]] auto build_state_response(database::PersistentStore const& store, std::string_view room_id)
    -> std::string;

// Builds the canonical-JSON response body for an inbound federation
// `GET /_matrix/federation/v1/state_ids/{roomId}?event_id=...` request.
// Returns event IDs only. Returns an empty string when the room has no
// recorded state.
[[nodiscard]] auto build_state_ids_response(database::PersistentStore const& store, std::string_view room_id)
    -> std::string;

// Builds the canonical-JSON response body for an inbound federation
// `POST /_matrix/federation/v1/get_missing_events/{roomId}` request.
// `request_body` is the `{earliest_events, latest_events, limit, min_depth}`
// query. Returns events in the room ordered by ascending depth, filtered by
// `min_depth` and capped by `limit`. Returns an empty string when the request
// body is not canonical-parseable.
[[nodiscard]] auto build_get_missing_events_response(database::PersistentStore const& store, std::string_view room_id,
                                                     std::string_view request_body) -> std::string;

} // namespace merovingian::federation
