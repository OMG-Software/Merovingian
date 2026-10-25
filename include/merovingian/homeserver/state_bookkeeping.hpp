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

namespace merovingian::config
{
struct FederationStateResolutionConfig;
}

// ADR-0064 phase B1: state bookkeeping for every stored event (local or
// federated) — state-before/state-after via delta state groups, forward
// extremities, and current state as a cache of the resolution over them.
// Shared between the inbound PDU sink (src/homeserver/local_http_router.cpp)
// and local event-creation paths (src/homeserver/room_service.cpp); see
// docs/adr/0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md.
namespace merovingian::homeserver
{

// Maps the operator's restart-required state-resolution budget to the
// resolver's typed limits. Kept in one place so every homeserver path uses
// the same policy.
[[nodiscard]] auto state_resolution_limits(config::FederationStateResolutionConfig const& config)
    -> events::StateResolutionLimits;

// Builds a store-backed events::EventLookupFn for the state-res v2
// auth-chain walk (auth difference / v12 conflicted state subgraph):
// resolves an event_id to a events::StateEventReference by parsing that
// event's stored JSON. Indexes `store.events` by event_id once per call, so
// callers that need many lookups (a single resolution) should build one
// instance and reuse it rather than calling this per lookup.
//
// This is the one lookup every state-group-aware code path uses; the
// separate lookup that used to live in local_http_router.cpp's
// `state_conflict_resolver` was deleted in ADR-0064 phase B2 along with the
// rest of that dead plumbing.
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
    // Why `ok` is false, for the caller's log; empty when it is true.
    std::string reason{};
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
                                        std::vector<std::string> const& prev_event_ids,
                                        events::StateResolutionLimits const& limits = {}) -> StateBeforeResult;

// State after an event = the state before it, plus the event itself when it
// is a state event (state_key has a value): upserts (event_type, state_key)
// -> event_id into a copy of `state_before`. Returns `state_before`
// unchanged (copied) for a non-state event.
[[nodiscard]] auto compute_state_after(std::vector<database::PersistentStateGroupStateEntry> const& state_before,
                                       std::string_view event_id, std::string_view event_type,
                                       std::optional<std::string> const& state_key)
    -> std::vector<database::PersistentStateGroupStateEntry>;

// Lower-level primitive behind record_event_state: creates or reuses a
// state group for `state_after` chained off an EXPLICIT `parent_group_id`
// (rather than one derived from a prev_event's own recorded group), maps
// `event_id` to it, and updates the room's forward extremities from
// `prev_event_ids_for_extremities` (those ids drop out, `event_id` becomes
// the new tip) — but only when `accepted` is true. Used directly by the
// federated-join seeding path (room_service.cpp), where the join event's
// "before" state is a synthetic snapshot built from the send_join response
// rather than any single prev_event's own recorded group.
//
// ADR-0064 phase B2: `accepted` distinguishes a normally-accepted event
// (the default, `true`) from a rejected or soft-failed one (`false`).
// database::update_forward_extremities is a no-op when `accepted` is false
// — per spec "Rejection"/"Soft failure", a rejected or soft-failed event is
// never added to the room's forward extremities, and its prev_events stay
// extremities in its place. The state group itself is still created/reused
// and the event is still mapped to it, since rejected and soft-failed
// events are both stored and (for soft-failed events) still take part in
// state resolution when a later event references them.
//
// Returns the state group id, or nullopt on a backend failure.
[[nodiscard]] auto record_event_state_with_parent(
    database::PersistentStore& store, std::string_view room_id, std::string_view event_id,
    std::vector<std::string> const& prev_event_ids_for_extremities, std::optional<std::string> const& parent_group_id,
    std::vector<database::PersistentStateGroupStateEntry> const& state_after, bool accepted = true)
    -> std::optional<std::string>;

// Records an event's post-state: creates or reuses a state group for
// `state_after` — chained off `prev_event_ids.front()`'s own state group as
// the delta parent when `prev_event_ids` is non-empty, so unchanged state
// reuses that group (see database::create_or_reuse_state_group) — maps
// `event_id` to the resulting group, and — when `accepted` is true (the
// default) — updates the room's forward extremities (`prev_event_ids` drop
// out, `event_id` becomes the new tip). See record_event_state_with_parent
// for what `accepted = false` means (ADR-0064 phase B2: a rejected or
// soft-failed event). Callers pass `state_before` (unchanged) as
// `state_after` for a rejected event (spec: "state...calculated as normal,
// except not updating with the rejected event"), and the normally-computed
// `compute_state_after` result for a soft-failed one (spec: soft-failed
// events "participate in state resolution as normal").
// Returns the state group id, or nullopt on a backend failure.
[[nodiscard]] auto record_event_state(database::PersistentStore& store, std::string_view room_id,
                                      std::string_view event_id, std::vector<std::string> const& prev_event_ids,
                                      std::vector<database::PersistentStateGroupStateEntry> const& state_after,
                                      bool accepted = true) -> std::optional<std::string>;

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
                                           rooms::RoomVersionPolicy const& policy,
                                           events::StateResolutionLimits const& limits = {}) -> bool;

// ---- Local event-creation choke point (ADR-0064 phase B1, continued) ----
//
// Every locally created event MUST go through forward_extremities_for_new_event
// (to choose prev_events) and then store_local_event (to persist it) —
// never database::store_event_with_state directly. A source-tree guard
// test (tests/unit/test_store_event_choke_point.cpp) fails the build if a
// src/ file other than this module and src/database/ calls it, so a future
// local path cannot silently bypass bookkeeping the way send_event and
// persist_composed_event previously did.

// Returns the prev_events a NEW local event should declare: the room's
// current forward extremities, capped at events::max_prev_events_per_event
// (spec: "Must contain less than or equal to 20 events") by keeping the
// highest-depth extremities when there are more. Call this before composing
// and signing a new event, since prev_events is itself a signed field.
[[nodiscard]] auto forward_extremities_for_new_event(database::PersistentStore const& store, std::string_view room_id)
    -> std::vector<std::string>;

// What a new local event is built on: the prev_events it declares and the
// state before it, resolved once, before the event is signed.
struct NewEventBasis final
{
    // False when no forward extremity has a state this server can compute;
    // the event must not be stored. `reason` says why.
    bool ok{false};
    std::vector<std::string> prev_event_ids{};
    std::vector<database::PersistentStateGroupStateEntry> state_before{};
    // Forward extremities the event does not cite because the state across
    // them could not be resolved. Storing the event removes them from the
    // room's extremities along with `prev_event_ids` (ADR-0225).
    std::vector<std::string> retired_extremities{};
    std::string reason{};
};

// Chooses the prev_events of a NEW local event and computes the state before
// it. Normally that is forward_extremities_for_new_event and the resolution of
// their states. When that resolution fails (an extremity with no recorded
// state, a missing auth-chain event, the state-resolution budget), it logs a
// warning and falls back to the newest extremity, by this server's stream
// order, whose state can be read alone, retiring every other extremity
// (ADR-0225). `ok` is false, with a warning logged, only when no extremity has
// a readable state. Call it under runtime.mutex, before composing and signing
// the event, and hand the result to store_local_event under the same hold.
[[nodiscard]] auto basis_for_new_event(database::PersistentStore const& store, std::string_view room_id,
                                       rooms::RoomVersionPolicy const& policy,
                                       events::StateResolutionLimits const& limits = {}) -> NewEventBasis;

// Stores a locally created, already-composed-and-signed `event` (and its
// `state` row, if it is a state event) and performs the same bookkeeping
// homeserver::ingest_pdu_event runs for inbound PDUs: stores the event via
// database::store_event_with_state, records its after-state group (from
// `basis.state_before`) and forward-extremity update (`basis.prev_event_ids`
// and `basis.retired_extremities` drop out), and recomputes current_state.
// `event.prev_event_ids` must be `basis.prev_event_ids`, which the caller
// signed into the event.
//
// Unlike ingest_pdu_event, every failure here is a HARD failure (returns
// false, with a warning naming the step): a local event has not yet been told
// "success" to any client or peer by the time this runs, so it is safe — and
// preferable — to fail the whole request rather than leave the store with an
// event whose bookkeeping is broken. A basis that is not `ok` stores nothing.
//
// Local events are authorised by the caller's own checks
// (events::authorize_event_against_auth_events, already run during
// composition); this function does not re-authorise.
//
// DB-4: `membership`, for an m.room.member event, is committed in the same
// transaction as the event and its current_state row (see
// database::MembershipProjection).
[[nodiscard]] auto store_local_event(database::PersistentStore& store, rooms::RoomVersionPolicy const& policy,
                                     database::PersistentEvent event,
                                     std::optional<database::PersistentStateEvent> state, NewEventBasis const& basis,
                                     events::StateResolutionLimits const& limits = {},
                                     std::optional<database::MembershipProjection> membership = std::nullopt) -> bool;

} // namespace merovingian::homeserver
