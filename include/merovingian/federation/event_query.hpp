// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/membership_endpoints.hpp"
#include "merovingian/federation/room_read_result.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

// Server-side caps for `POST /get_missing_events`. The spec default for `limit`
// is 10; the cap bounds how much history one request can pull. `latest_events`
// is capped because every entry costs one lookup in the event store.
inline constexpr auto default_missing_events_limit = std::size_t{10U};
inline constexpr auto max_missing_events_limit = std::size_t{20U};
inline constexpr auto max_missing_events_latest = std::size_t{100U};

// True when `origin` may read `room_id` over federation: the room's CURRENT state
// holds a `m.room.member` event with `membership: join` for a user whose server
// name is exactly `origin`, or the room's current `m.room.history_visibility` is
// `world_readable`. An unknown room, an empty origin, an invite, a leave or a
// ban all answer false. This is the FED-2 gate: every room-scoped federation
// read calls it (directly or through the builders below) with the X-Matrix
// authenticated origin, never with a value taken from the request.
[[nodiscard]] auto origin_may_read_room(database::PersistentStore const& store, std::string_view room_id,
                                        std::string_view origin) -> bool;

// Builds the response for an inbound federation
// `GET /_matrix/federation/v1/event/{eventId}` request. The event's own room is
// resolved from the store and `origin` must pass `origin_may_read_room` and the
// room's server ACL for it. An unknown event is `not_found`; a known event in a
// room the origin cannot read is `forbidden`.
[[nodiscard]] auto build_event_response(database::PersistentStore const& store, std::string_view event_id,
                                        std::string_view local_server_name, std::string_view origin) -> RoomReadResult;

// Builds the response for an inbound federation
// `GET /_matrix/federation/v1/state/{roomId}?event_id=...` request. `origin`
// must pass `origin_may_read_room` for `room_id` (checked first, so a stranger
// learns nothing about the event). The state is reconstructed as of
// `at_event_id` -- the fully resolved state prior to the changes the event itself
// induces (SS API §GET /state/{roomId}) -- by walking the event DAG backward from
// the event's `prev_events`, and comes back in `pdus` with the transitive
// auth-event closure of that state in `auth_chain`. An `at_event_id` that is
// empty, unknown or not in `room_id` is `not_found`: there is deliberately no
// fallback to the room's current state.
[[nodiscard]] auto build_state_response(database::PersistentStore const& store, std::string_view room_id,
                                        std::string_view at_event_id, std::string_view origin) -> RoomReadResult;

// As `build_state_response`, for `GET /state_ids/{roomId}`: the state event IDs
// in `pdu_ids` and the auth-event closure in `auth_chain_ids`.
[[nodiscard]] auto build_state_ids_response(database::PersistentStore const& store, std::string_view room_id,
                                            std::string_view at_event_id, std::string_view origin) -> RoomReadResult;

// Resolves the state event IDs describing "the room state at `at_event_id`"
// -- state that includes any change `at_event_id` itself induces when it is a
// state event. This is the sense the client-server API's `GET /messages`-
// adjacent endpoints need (e.g. CS API `GET /rooms/{roomId}/context/{eventId}`:
// "The state of the room at the last event returned"), which is distinct from
// `build_state_response`'s federation-facing "state prior to this event"
// (SS API `GET /state/{roomId}`: "prior to considering any state changes
// induced by the requested event"). Reuses the same backward DAG walk from
// `at_event_id`'s `prev_events` that `build_state_response`/
// `build_state_ids_response` use, then folds `at_event_id` itself back in as
// the winning entry for its own (type, state_key) when it is a state event.
// Falls back to the room's current recorded state when `at_event_id` is empty
// or does not name a stored event belonging to `room_id`.
[[nodiscard]] auto resolve_state_event_ids_at(database::PersistentStore const& store, std::string_view room_id,
                                              std::string_view at_event_id = {}) -> std::vector<std::string>;

// Builds the PDU list for `GET /_matrix/federation/v1/backfill/{roomId}` by
// starting at each requested event ID and walking `prev_events` until `limit`
// PDUs have been collected. Missing events and events outside `room_id` are
// skipped.
[[nodiscard]] auto build_backfill_pdus(database::PersistentStore const& store, std::string_view room_id,
                                       std::vector<std::string> const& event_ids, std::size_t limit)
    -> std::vector<std::string>;

// Serves `GET /_matrix/federation/v1/backfill/{roomId}`: 403 M_FORBIDDEN unless
// `request.origin` passes `origin_may_read_room`, otherwise the PDUs from
// `build_backfill_pdus`.
[[nodiscard]] auto build_backfill_response(database::PersistentStore const& store,
                                           BackfillRequest const& request) -> BackfillResult;

// Builds the response for an inbound federation
// `POST /_matrix/federation/v1/get_missing_events/{roomId}` request.
// `request_body` is the `{earliest_events, latest_events, limit, min_depth}`
// query. `origin` must pass `origin_may_read_room` (checked before the body is
// looked at). Per SS API §POST /get_missing_events the result is a breadth-first
// walk of `prev_events` from `latest_events`: it never returns or walks past an
// event in `earliest_events`, never returns the `latest_events` themselves, skips
// (and does not walk past) events with `depth` below `min_depth`, and stops at
// `limit` (default 10, at most 20). Events come back oldest first. The walk
// touches at most a bounded number of events and never scans the room. A body
// that is not a JSON object with string-list `latest_events` and `earliest_events`
// (at most `max_missing_events_latest` latest events) and integer `limit` /
// `min_depth` is `malformed`.
[[nodiscard]] auto build_get_missing_events_response(database::PersistentStore const& store, std::string_view room_id,
                                                     std::string_view request_body,
                                                     std::string_view origin) -> RoomReadResult;

} // namespace merovingian::federation
