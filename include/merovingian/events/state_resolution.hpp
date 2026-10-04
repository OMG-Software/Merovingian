// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/events/limits.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace merovingian::events
{

struct StateKey final
{
    std::string event_type{};
    std::string state_key{};

    [[nodiscard]] auto operator==(StateKey const& other) const noexcept -> bool
    {
        return event_type == other.event_type && state_key == other.state_key;
    }
};

struct StateKeyHash final
{
    [[nodiscard]] auto operator()(StateKey const& key) const noexcept -> std::size_t
    {
        auto h = std::hash<std::string>{};
        return h(key.event_type) ^ (h(key.state_key) * 31);
    }
};

struct StateEventReference final
{
    StateKey key{};
    std::string event_id{};
    std::string sender{};
    std::int64_t origin_server_ts{0};
    std::uint64_t depth{0};
    canonicaljson::Value event_json{};
};

struct StateGroup final
{
    std::string group_id{};
    std::vector<StateEventReference> state{};
};

// Fetches a single event (by id) that is not present in any submitted state
// group, so the resolver can walk auth_events chains past the two forked
// state snapshots it was handed. Returns nullopt when the event is unknown
// to the caller (e.g. not yet persisted). The resolver treats any such miss
// encountered while walking an auth chain as fatal to the whole resolution
// (fail closed) rather than proceeding with a partial chain — see
// resolve_state_v2.
// Spec: ../../docs/matrix-v1.19-spec/rooms/v10.md — Definitions ("Auth
// chain", "Auth difference").
using EventLookupFn = std::function<std::optional<StateEventReference>(std::string_view event_id)>;

struct StateResolutionRequest final
{
    std::string room_version{};
    std::vector<StateGroup> state_groups{};
    EventLookupFn event_lookup{};
    // Required for room v12 (MSC4291, StateResolutionAlgorithm::v2_1)
    // resolutions: the m.room.create event is implicit in the room ID
    // (rooms/v12.md rule 2 — "!" + the create event's own reference hash),
    // and resolve_state_v2 derives the create event's id from this field
    // and fetches it through `event_lookup` (or a submitted state group)
    // to seed the iterative auth checks' otherwise-empty starting map —
    // see resolve_state_v2's implementation comment. Left empty for a
    // non-v12 resolution, which does not need it. A v12 resolution whose
    // derived create event cannot be fetched fails closed (ADR-0063)
    // rather than falling back to the state groups' own (spoofable)
    // unconflicted agreement — but a v12 resolution given no `room_id` at
    // all still falls back to that unconflicted agreement, for callers
    // (this module's own unit tests) using synthetic event ids that do not
    // follow the MSC4291 room_id convention. Every real production caller
    // (compute_state_before, recompute_current_state) always supplies
    // `room_id`, so that fallback is never reachable from untrusted
    // federation input.
    std::string room_id{};
};

struct StateResolutionResult final
{
    bool resolved{false};
    std::vector<StateEventReference> resolved_state{};
    std::string reason{};
};

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
[[nodiscard]] auto partition_conflicted_state(std::vector<StateGroup> const& groups) -> std::pair<StateMap, StateMap>;
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
                                                  rooms::RoomVersionPolicy const& policy)
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
                    EventJsonIndex const& events_by_id) -> void;

} // namespace merovingian::events
