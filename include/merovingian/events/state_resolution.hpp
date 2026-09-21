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

struct EventPowerData final
{
    std::int64_t sender_power{0};
    std::int64_t origin_server_ts{0};
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

[[nodiscard]] auto partition_conflicted_state(std::vector<StateGroup> const& groups) -> std::pair<StateMap, StateMap>;
// `policy` decides how a sender's power level is read: room versions 1-9 accept
// a power level encoded as a JSON string, v10+ require a real integer. The
// ordering ranks events by sender power, so reading a v9 string level as absent
// would demote the sender to users_default and let a lower-power event win.
// Spec: ../../docs/matrix-v1.19-spec/rooms/v10.md — "Values in
// m.room.power_levels events must be integers".
[[nodiscard]] auto reverse_topological_power_sort(std::vector<StateEventReference> const& conflicted,
                                                  StateMap const& unconflicted, rooms::RoomVersionPolicy const& policy)
    -> std::vector<StateEventReference>;

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
