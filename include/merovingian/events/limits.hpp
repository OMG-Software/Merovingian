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

} // namespace merovingian::events
