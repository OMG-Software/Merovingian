// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/events/StateEventReference.hpp"    // split-shim
#include "merovingian/events/StateGroup.hpp"             // split-shim
#include "merovingian/events/StateKey.hpp"               // split-shim
#include "merovingian/events/StateKeyHash.hpp"           // split-shim
#include "merovingian/events/StateResolutionLimits.hpp"  // split-shim
#include "merovingian/events/StateResolutionRequest.hpp" // split-shim
#include "merovingian/events/StateResolutionResult.hpp"  // split-shim
#include "merovingian/events/limits.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace merovingian::events
{

using StateMap = std::unordered_map<StateKey, StateEventReference, StateKeyHash>;

// Index of event JSON by event id, used by the mainline walk to follow
// auth_events links. The referenced values must outlive the index (they are
// views into the StateResolutionRequest's state groups).
using EventJsonIndex = std::unordered_map<std::string, std::reference_wrapper<canonicaljson::Value const>>;

[[nodiscard]] auto state_key_matches(StateKey const& left, StateKey const& right) noexcept -> bool;
[[nodiscard]] auto state_group_contains(StateGroup const& group, StateKey const& key) noexcept -> bool;
[[nodiscard]] auto state_group_event(StateGroup const& group, StateKey const& key) noexcept
    -> StateEventReference const*;
[[nodiscard]] auto resolve_state(StateResolutionRequest const& request) -> StateResolutionResult;
[[nodiscard]] auto resolve_state_v2(StateResolutionRequest const& request, rooms::RoomVersionPolicy const& policy)
    -> StateResolutionResult;
[[nodiscard]] auto state_resolution_summary(StateResolutionResult const& result) -> std::string;

// Splits the state groups into {unconflicted, conflicted}. Spec
// (rooms/v10.md — Definitions): a key is unconflicted only if it is present in
// EVERY group with the same single event; otherwise every value of that key
// belongs to the conflicted set and the key never appears in `unconflicted`,
// whatever the number or order of groups. `conflicted` is a key index (one
// representative event per conflicted key) — the caller gathers every distinct
// value from the groups. Returns two empty maps when the number of distinct
// keys exceeds `max_conflicted_state_keys`.
[[nodiscard]] auto partition_conflicted_state(std::vector<StateGroup> const& groups,
                                              StateResolutionLimits const& limits = {})
    -> std::pair<StateMap, StateMap>;
// Each candidate's sender power is read from the m.room.power_levels event
// in THAT CANDIDATE'S OWN auth_events — never
// from the candidate's own new content, and never from a shared
// unconflicted/resolved state map. `known_events` supplies auth_events
// ancestors already present in the submitted state groups; `event_lookup`
// (may be empty) supplies anything else. `policy` additionally decides how a
// sender's power level is read once the power_levels event is found: room
// versions 1-9 accept a power level encoded as a JSON string, v10+ require a
// real integer, and v12 gives room creators an effectively infinite level
// (MSC4289). The implicit v12 create event is fetched using the create-event
// ID derived from the candidate's room_id, not from explicit auth_events.
// Returns
// nullopt when an auth_events entry needed to answer the question could not
// be resolved — fail closed (ADR-0063), never order by a partially-known
// chain.
// Spec: ../../docs/matrix-v1.19-spec/rooms/v10.md — Definitions, "Reverse
// topological power ordering", rule 1 ("looking at their respective
// auth_events"); "Values in m.room.power_levels events must be integers".
// The order is Kahn's algorithm over the auth_events DAG restricted to
// `conflicted` (an event follows every event it cites that is also in the
// set), choosing at each step the smallest ready event: sender power
// descending, then origin_server_ts ascending, then event_id ascending. Also
// returns nullopt for a duplicate event id or a cycle in the auth graph.
[[nodiscard]] auto reverse_topological_power_sort(std::vector<StateEventReference> const& conflicted,
                                                  EventJsonIndex const& known_events, EventLookupFn const& event_lookup,
                                                  rooms::RoomVersionPolicy const& policy,
                                                  StateResolutionLimits const& limits = {})
    -> std::optional<std::vector<StateEventReference>>;

// Spec (rooms/v10 — Definitions, Power events): a power event is an
// m.room.power_levels or m.room.join_rules state event, or an m.room.member
// event with membership leave/ban whose sender differs from the state_key.
[[nodiscard]] auto is_power_event(StateEventReference const& event) noexcept -> bool;

[[nodiscard]] auto build_event_json_index(std::vector<StateGroup> const& groups) -> EventJsonIndex;

// Sort `events` by the mainline ordering based on the m.room.power_levels
// event in `resolved` (the partially resolved state after power events have
// been auth-checked). `events_by_id` supplies event JSON for the transitive
// auth_events walk.
auto mainline_order(std::vector<StateEventReference>& events, StateMap const& resolved,
                    EventJsonIndex const& events_by_id, StateResolutionLimits const& limits = {}) -> void;

} // namespace merovingian::events
