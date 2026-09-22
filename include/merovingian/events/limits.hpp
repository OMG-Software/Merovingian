// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>

namespace merovingian::events
{

// Public resource limits for federation event/state processing.
// These caps are deliberately high: they must not affect legitimate rooms
// (even very large ones) but they must fail fast on pathological DoS payloads
// before expensive sorting, auth-chain walking, or signature verification.

// ---- Signature parsing limits ----

// Maximum number of signatures accepted from a single server for one event.
// A real homeserver normally presents one or two key IDs per server; 100
// leaves headroom for key rotations while preventing quadratic memory growth.
inline constexpr std::size_t max_signatures_per_server = 100U;

// Maximum number of distinct servers that may appear in an event's
// "signatures" object. Federation events are signed by the origin server and
// potentially a few notary servers; 50 is far above legitimate usage.
inline constexpr std::size_t max_servers_with_signatures = 50U;

// Maximum total signatures on a single event (origin + notaries + key ids).
// Bounded below by the product of the per-server and per-server-name caps.
inline constexpr std::size_t max_signatures_per_event = 5'000U;

// ---- State resolution limits ----

// Maximum number of distinct state groups that may be submitted in a single
// resolution request. Typical room forks involve a handful of groups;
// 1 000 covers large federated merges without permitting adversarial growth.
inline constexpr std::size_t max_state_groups = 1'000U;

// Maximum number of state events in a single state group. Large rooms may have
// tens of thousands of state events, but processing is O(N log N); 10 000
// keeps worst-case work bounded while still supporting ordinary large rooms.
inline constexpr std::size_t max_events_per_state_group = 10'000U;

// Maximum number of conflicted state keys the resolver will consider before
// giving up. Derived from the maximum number of events across all groups.
inline constexpr std::size_t max_conflicted_state_keys = 10'000U;

// Maximum depth the auth-chain/mainline walker will follow. State resolution
// v2 orders power-levels events by their position on the mainline; real rooms
// have depth in the hundreds, so 10 000 prevents infinite or cyclic chains.
inline constexpr std::size_t max_mainline_auth_chain_depth = 10'000U;

// Maximum number of events the state-resolution auth-chain walker will fetch
// (via StateResolutionRequest::event_lookup) or visit while computing the
// auth difference, the v12 conflicted state subgraph, and the iterative auth
// checks' own-auth-events fallback. This walk is reachable from untrusted
// federation input (a hostile remote can propose a state fork), so it must
// be bounded independently of the room's real size; 20 000 comfortably
// covers a legitimate room's auth chain while still failing closed on an
// adversarially deep or wide chain.
// Spec: ../../docs/matrix-v1.19-spec/rooms/v10.md — Definitions ("Auth
// chain", "Auth difference"); ../../docs/matrix-v1.19-spec/rooms/v12.md —
// Definitions ("Conflicted state subgraph").
inline constexpr std::size_t max_auth_chain_walk_events = 20'000U;

// ---- Delta state group limits (ADR-0064) ----

// Maximum number of parent hops a state group's delta chain may have before a
// new group must be written as a full snapshot instead of a further delta.
// Bounds the cost of database::read_state_group_full_state, which walks the
// chain back to its snapshot and applies every delta on the way; without a
// cap a room with a very long, unbroken run of single-key state changes
// (e.g. sustained membership churn) would make every state read walk an
// ever-growing chain. 100 keeps that walk cheap while still amortising the
// snapshot's storage cost across many deltas for ordinary rooms.
inline constexpr std::size_t max_state_group_delta_depth = 100U;

// ---- Event graph limits ----

// Maximum number of prev_events a single event may declare. Spec (every
// room version's event format, rooms/v1.md through rooms/v12.md):
// "Must contain less than or equal to 20 events." Locally created events
// take their prev_events from the room's current forward extremities
// (ADR-0064 phase B1); when there are more than this many, the highest-
// depth ones are kept.
inline constexpr std::size_t max_prev_events_per_event = 20U;

} // namespace merovingian::events
