// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/events/state_resolution.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <cstdint>
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
// event's stored JSON. Each call is one `EventTable::find` hash lookup
// (ADR-0215, ADR-0325): building the function costs nothing, and a lookup costs
// the event asked for, not the number of events the server stores. It reads
// `store` on every call, so the store must outlive the function.
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

// How a recomputation of the room's current state ended (F-49, ADR-0375).
enum class CurrentStateRecomputeStatus : std::uint8_t
{
    // Current state is the resolution of the room's forward extremities: it was written where it
    // differed, or the room has no extremity to resolve.
    resolved,
    // The extremities could not be resolved (an extremity with no readable state, more extremities
    // than `max_state_groups`, the state budget, a missing auth-chain event, or a resolution that
    // fails closed). Current state was not touched, so it is NOT the resolution of the extremities:
    // each accepted event has put only its own row in it since. Logged at warning level.
    refused,
    // A diffed entry could not be written.
    write_failed,
};

struct CurrentStateRecompute final
{
    CurrentStateRecomputeStatus status{CurrentStateRecomputeStatus::resolved};
    // Why the extremities could not be resolved; empty unless `status` is `refused`.
    std::string reason{};

    // True only when current state is the resolution of the extremities.
    [[nodiscard]] explicit operator bool() const noexcept
    {
        return status == CurrentStateRecomputeStatus::resolved;
    }
};

// Recomputes the room's current state as the state resolution over its
// forward extremities' after-states (one extremity: that state directly, no
// resolution needed), diffs it against the cached `current_state`, and
// writes only the (event_type, state_key) entries that changed through
// database::store_state — the same call every other state write already
// goes through, so `state_transitions` (unsigned.replaces_state) and every
// existing sync-detection path stay correct; current_state is never written
// to directly elsewhere.
//
// An empty extremity set has nothing to resolve and is `resolved`. Extremities held in one state
// group are one state. A missing state group on an extremity, more distinct states than
// `limits.max_state_groups`, the state budget or a resolution that fails closed is `refused`
// (F-49, ADR-0375): current_state is left as it is and a warning names the room and the reason.
// That is reachable from the network (a member's many profile-change forks, a large room's
// state budget), so a caller must not read it as success: until the next recomputation resolves,
// current state is the cache it was plus each accepted event's own row. `write_failed` is a
// backend write failure.
[[nodiscard]] auto recompute_current_state(database::PersistentStore& store, std::string_view room_id,
                                           rooms::RoomVersionPolicy const& policy,
                                           events::StateResolutionLimits const& limits = {}) -> CurrentStateRecompute;

// Whether an accepted event that adds NO state (a message, a receipt-less event: no state_key) with
// these prev_events may become one of `room_id`'s forward extremities without taking their
// number past `limits.max_state_groups` (F-49, ADR-0374). An event that cites a current
// extremity replaces it and never grows the set, so it is always allowed; one that cites only
// older events adds a tip, and past the limit it is refused. The caller still stores, delivers
// and places such an event by its own prev_events; it only does not make it a tip. A state event
// is always a tip (a ban or a demotion must reach resolution), and a local event retires the tips
// it cites, so neither asks. recompute_current_state resolves extremities that share a state
// group as one state, so the tips this bounds cost resolution nothing.
[[nodiscard]] auto forward_extremities_stay_bounded(database::PersistentStore const& store, std::string_view room_id,
                                                    std::vector<std::string> const& prev_event_ids,
                                                    events::StateResolutionLimits const& limits) -> bool;

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

// The depth of an event built on `prev_event_ids`. Spec (rooms/v11.md, `depth`): "The maximum depth
// of the prev_events, plus one", and "If the room's depth is already at the limit, the depth must be
// set to the limit." ADR-0314: only the events it is built on count, never every row of the room,
// because a rejected row keeps whatever depth its sender chose.
[[nodiscard]] auto depth_after_prev_events(database::PersistentStore const& store,
                                           std::vector<std::string> const& prev_event_ids) -> std::uint64_t;

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
// order, whose state can be read alone, as the one prev_event, retiring every
// other extremity (ADR-0225). The state before a fallback event is the room's
// cached current_state, NOT that extremity's own after-state (F-40, ADR-0373):
// a retired tip may carry a ban or demotion the cited fork lacks, and current
// state still holds it. A room with no current_state row (degenerate) uses the
// extremity's state. `ok` is false, with a warning logged, only when no
// extremity has a readable state. Call it under runtime.mutex, before composing and signing
// the event, and hand the result to store_local_event under the same hold.
[[nodiscard]] auto basis_for_new_event(database::PersistentStore const& store, std::string_view room_id,
                                       rooms::RoomVersionPolicy const& policy,
                                       events::StateResolutionLimits const& limits = {}) -> NewEventBasis;

// How an event this server places itself is recorded: the state after it, the
// group that state is a delta of (nullopt: a full snapshot), and the forward
// extremities it replaces as the room's tip.
struct EventBookkeeping final
{
    std::vector<database::PersistentStateGroupStateEntry> state_after{};
    std::optional<std::string> parent_state_group_id{};
    std::vector<std::string> replaced_extremities{};
};

// Whether store_event_with_bookkeeping stored the event, and if not, the step
// that refused it (`event`, `state_group`, `current_state` or `commit`) and why.
struct StoredWithBookkeeping final
{
    bool ok{false};
    std::string step{};
    std::string reason{};
    // True when the event was stored but the room's forward extremities could not be resolved
    // (F-49), so current state holds only the event's own row beyond what it already held. A
    // warning was logged. `resolution_refusal` says why.
    bool resolution_refused{false};
    std::string resolution_refusal{};
};

// Stores an event this server places itself (a local event, or the join event
// of a federated join) with all of its bookkeeping in ONE transaction
// (ADR-0228): the event and its current_state row, `membership` (DB-4), its
// after-state group, its mapping to that group, the forward-extremity change,
// and whatever the resolution of the resulting extremities changes in current
// state. Nothing is written unless all of it is, so a refusal leaves no event,
// membership, group or tip behind. When the extremities cannot be resolved the event is still
// stored, current state is left to its own row, and the result says so (`resolution_refused`).
// Call it under runtime.mutex.
[[nodiscard]] auto store_event_with_bookkeeping(
    database::PersistentStore& store, rooms::RoomVersionPolicy const& policy, database::PersistentEvent event,
    std::optional<database::PersistentStateEvent> state, std::optional<database::MembershipProjection> membership,
    EventBookkeeping const& bookkeeping, events::StateResolutionLimits const& limits = {}) -> StoredWithBookkeeping;

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
// event whose bookkeeping is broken. A basis that is not `ok` stores nothing,
// and the rest commits in one transaction (store_event_with_bookkeeping).
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
