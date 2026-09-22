// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/state_resolution.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

// ADR-0064 phase B1: state bookkeeping for every stored event (local or
// federated) — state-before/state-after via delta state groups, forward
// extremities, and current state as a cache of the resolution over them.
// Shared between the inbound PDU sink (src/homeserver/local_http_router.cpp)
// and local event-creation paths (src/homeserver/room_service.cpp); see
// docs/adr/0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md.
namespace merovingian::homeserver
{

// Builds a store-backed events::EventLookupFn for the state-res v2
// auth-chain walk (auth difference / v12 conflicted state subgraph):
// resolves an event_id to a events::StateEventReference by parsing that
// event's stored JSON. Indexes `store.events` by event_id once per call, so
// callers that need many lookups (a single resolution) should build one
// instance and reuse it rather than calling this per lookup.
//
// This is a separate lookup from the one wired into the dead
// `state_conflict_resolver` plumbing in local_http_router.cpp (left
// unchanged in phase B1, see the comment there) — every new state-group-
// aware code path uses this one instead.
[[nodiscard]] auto make_store_event_lookup(database::PersistentStore const& store) -> events::EventLookupFn;

// Result of resolving the state immediately before an event from its
// prev_event_ids.
struct StateBeforeResult final
{
    // False when a prev_event has no recorded state group (an older,
    // pre-Phase-A event, or a genuine gap in our history of the room), or
    // resolution itself failed closed (an unreachable/missing auth-chain
    // event, or the walk cap — see ADR-0063). Either way the caller must not
    // store the event or substitute current state; see
    // federation::PduIngestionStatus::missing_prev_state.
    bool ok{false};
    std::vector<database::PersistentStateGroupStateEntry> state{};
};

// State before an event = the state resolution of the states after each of
// `prev_event_ids`: with a single prev_event this is that event's own
// after-state, no resolution needed; with several it is
// events::resolve_state_v2 over their after-states. Empty `prev_event_ids`
// (valid only for a room's first event, m.room.create) resolves to the
// empty state.
// Spec: docs/matrix-v1.19-spec/server-server-api.md — "Checks performed on
// receipt of a PDU".
[[nodiscard]] auto compute_state_before(database::PersistentStore const& store, std::string_view room_id,
                                        rooms::RoomVersionPolicy const& policy,
                                        std::vector<std::string> const& prev_event_ids) -> StateBeforeResult;

// State after an event = the state before it, plus the event itself when it
// is a state event (state_key has a value): upserts (event_type, state_key)
// -> event_id into a copy of `state_before`. Returns `state_before`
// unchanged (copied) for a non-state event.
[[nodiscard]] auto compute_state_after(std::vector<database::PersistentStateGroupStateEntry> const& state_before,
                                       std::string_view event_id, std::string_view event_type,
                                       std::optional<std::string> const& state_key)
    -> std::vector<database::PersistentStateGroupStateEntry>;

// Records an accepted event's post-state: creates or reuses a state group
// for `state_after` — chained off `prev_event_ids.front()`'s own state
// group as the delta parent when `prev_event_ids` is non-empty, so unchanged
// state reuses that group (see database::create_or_reuse_state_group) —
// maps `event_id` to the resulting group, and updates the room's forward
// extremities (`prev_event_ids` drop out, `event_id` becomes the new tip).
// Returns the state group id, or nullopt on a backend failure.
[[nodiscard]] auto record_event_state(database::PersistentStore& store, std::string_view room_id,
                                      std::string_view event_id, std::vector<std::string> const& prev_event_ids,
                                      std::vector<database::PersistentStateGroupStateEntry> const& state_after)
    -> std::optional<std::string>;

// Recomputes the room's current state as the state resolution over its
// forward extremities' after-states (one extremity: that state directly, no
// resolution needed), diffs it against the cached `current_state`, and
// writes only the (event_type, state_key) entries that changed through
// database::store_state — the same call every other state write already
// goes through, so `state_transitions` (unsigned.replaces_state) and every
// existing sync-detection path stay correct; current_state is never written
// to directly elsewhere.
//
// Returns false only on a backend write failure while applying a diffed
// entry. An empty extremity set, a missing state group on an extremity, or
// an unresolvable fork all leave the cached current_state untouched (a
// no-op, not an error) rather than risk corrupting it — every accepted
// event recorded through record_event_state always has a state group, so
// these are defensive fallbacks for degenerate inputs, not an expected
// runtime path.
[[nodiscard]] auto recompute_current_state(database::PersistentStore& store, std::string_view room_id,
                                           rooms::RoomVersionPolicy const& policy) -> bool;

} // namespace merovingian::homeserver
