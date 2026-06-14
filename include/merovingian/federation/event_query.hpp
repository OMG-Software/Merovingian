// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

// Builds the canonical-JSON response body for an inbound federation
// `GET /_matrix/federation/v1/event/{eventId}` request. Returns an empty
// string when the requested event is not in the store.
[[nodiscard]] auto build_event_response(database::PersistentStore const& store, std::string_view event_id,
                                        std::string_view origin_server_name) -> std::string;

// Builds the canonical-JSON response body for an inbound federation
// `GET /_matrix/federation/v1/state/{roomId}?event_id=...` request. Returns the
// resolved room state in `pdus` and the transitive auth-event closure of that
// state in `auth_chain`. When `at_event_id` names an event in the room, the
// state is reconstructed as of that event — the fully resolved state prior to
// the changes the event itself induces (SS API §GET /state/{roomId}) — by
// walking the event DAG backward from the event's `prev_events`. When
// `at_event_id` is empty or unknown, the room's current state is returned.
// Returns an empty string when the room has no resolvable state.
[[nodiscard]] auto build_state_response(database::PersistentStore const& store, std::string_view room_id,
                                        std::string_view at_event_id = {}) -> std::string;

// Builds the canonical-JSON response body for an inbound federation
// `GET /_matrix/federation/v1/state_ids/{roomId}?event_id=...` request. Returns
// the resolved state event IDs in `pdu_ids` and the transitive auth-event
// closure of that state in `auth_chain_ids`. State is reconstructed as of
// `at_event_id` when it names an event in the room (see `build_state_response`),
// otherwise the room's current state IDs are returned. Returns an empty string
// when the room has no resolvable state.
[[nodiscard]] auto build_state_ids_response(database::PersistentStore const& store, std::string_view room_id,
                                            std::string_view at_event_id = {}) -> std::string;

// Builds the PDU list for `GET /_matrix/federation/v1/backfill/{roomId}` by
// starting at each requested event ID and walking `prev_events` until `limit`
// PDUs have been collected. Missing events and events outside `room_id` are
// skipped.
[[nodiscard]] auto build_backfill_pdus(database::PersistentStore const& store, std::string_view room_id,
                                       std::vector<std::string> const& event_ids, std::size_t limit)
    -> std::vector<std::string>;

// Builds the canonical-JSON response body for an inbound federation
// `POST /_matrix/federation/v1/get_missing_events/{roomId}` request.
// `request_body` is the `{earliest_events, latest_events, limit, min_depth}`
// query. Returns events in the room ordered by ascending depth, filtered by
// `min_depth` and capped by `limit`. Returns an empty string when the request
// body is not canonical-parseable.
[[nodiscard]] auto build_get_missing_events_response(database::PersistentStore const& store, std::string_view room_id,
                                                     std::string_view request_body) -> std::string;

} // namespace merovingian::federation
