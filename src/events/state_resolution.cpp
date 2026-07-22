// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/events/state_resolution.hpp"

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/events/limits.hpp"
#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <unordered_set>
#include <utility>
#include <variant>
#include <vector>

namespace merovingian::events
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("state_resolution", event, fields, severity);
    }

    [[nodiscard]] auto object_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Value const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return member.value.get();
            }
        }

        return nullptr;
    }

    [[nodiscard]] auto string_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::string const*
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<std::string>(&value->storage());
    }

    [[nodiscard]] auto integer_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> std::int64_t const*
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<std::int64_t>(&value->storage());
    }

    [[nodiscard]] auto object_member_as_object(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Object const*
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<canonicaljson::Object>(&value->storage());
    }

    [[nodiscard]] auto value_is_object(canonicaljson::Value const& value) noexcept -> canonicaljson::Object const*
    {
        return std::get_if<canonicaljson::Object>(&value.storage());
    }

    [[nodiscard]] auto array_member(canonicaljson::Object const& object, std::string_view key) noexcept
        -> canonicaljson::Array const*
    {
        auto const* value = object_member(object, key);
        if (value == nullptr)
        {
            return nullptr;
        }
        return std::get_if<canonicaljson::Array>(&value->storage());
    }

    // Extract the event id from one auth_events entry. v3+ rooms use plain
    // event-id strings; v1/v2 rooms use [event_id, hash] pairs.
    [[nodiscard]] auto auth_entry_event_id(canonicaljson::Value const& entry) noexcept -> std::string const*
    {
        if (auto const* id = std::get_if<std::string>(&entry.storage()); id != nullptr)
        {
            return id;
        }
        if (auto const* pair = std::get_if<canonicaljson::Array>(&entry.storage()); pair != nullptr && !pair->empty())
        {
            return std::get_if<std::string>(&pair->front().storage());
        }
        return nullptr;
    }

    // Find the m.room.power_levels event among `event_json`'s auth_events.
    // Returns the ancestor's id, or nullptr if none is present or its JSON is
    // not available in the index (the walk cannot continue past unknown events).
    [[nodiscard]] auto power_levels_auth_ancestor(canonicaljson::Object const& event_json,
                                                  EventJsonIndex const& events_by_id) -> std::string const*
    {
        auto const* auth = array_member(event_json, "auth_events");
        if (auth == nullptr)
        {
            return nullptr;
        }
        for (auto const& entry : *auth)
        {
            auto const* id = auth_entry_event_id(entry);
            if (id == nullptr)
            {
                continue;
            }
            auto const it = events_by_id.find(*id);
            if (it == events_by_id.end())
            {
                continue;
            }
            auto const* obj = value_is_object(it->second.get());
            if (obj == nullptr)
            {
                continue;
            }
            auto const* type = string_member(*obj, "type");
            if (type != nullptr && *type == "m.room.power_levels")
            {
                return &it->first;
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto value_has_content(canonicaljson::Value const& value) noexcept -> bool
    {
        return !std::holds_alternative<std::nullptr_t>(value.storage());
    }

    [[nodiscard]] auto select_v1_winner(StateEventReference const& existing,
                                        StateEventReference const& candidate) noexcept -> StateEventReference const&
    {
        if (candidate.depth != existing.depth)
        {
            return candidate.depth > existing.depth ? candidate : existing;
        }
        return candidate.event_id < existing.event_id ? candidate : existing;
    }

    [[nodiscard]] auto extract_user_power(canonicaljson::Value const& power_levels_event,
                                          std::string_view user_id) noexcept -> std::int64_t
    {
        auto const* obj = value_is_object(power_levels_event);
        if (obj == nullptr)
        {
            return 0;
        }
        auto const* content = object_member_as_object(*obj, "content");
        if (content == nullptr)
        {
            return 0;
        }
        auto const default_level = [&]() -> std::int64_t {
            auto const* level = integer_member(*content, "users_default");
            return level != nullptr ? *level : 0;
        }();
        auto const* users = object_member_as_object(*content, "users");
        if (users == nullptr)
        {
            return default_level;
        }
        auto const* level = integer_member(*users, std::string{user_id});
        return level != nullptr ? *level : default_level;
    }

    [[nodiscard]] auto power_level_from_event(StateEventReference const& event, StateMap const& unconflicted) noexcept
        -> std::int64_t
    {
        if (event.key.event_type == "m.room.power_levels" && event.key.state_key.empty())
        {
            auto const sender_power = extract_user_power(event.event_json, event.sender);
            return sender_power;
        }
        auto const pl_key = StateKey{"m.room.power_levels", ""};
        auto const it = unconflicted.find(pl_key);
        if (it != unconflicted.end() && value_has_content(it->second.event_json))
        {
            return extract_user_power(it->second.event_json, event.sender);
        }
        return 0;
    }

    [[nodiscard]] auto event_power_data(StateEventReference const& event, StateMap const& unconflicted) noexcept
        -> EventPowerData
    {
        return {power_level_from_event(event, unconflicted), event.origin_server_ts};
    }

    struct ReverseTopoCompare final
    {
        StateMap const& unconflicted;

        [[nodiscard]] auto operator()(StateEventReference const& a, StateEventReference const& b) const noexcept -> bool
        {
            auto const pa = event_power_data(a, unconflicted);
            auto const pb = event_power_data(b, unconflicted);

            if (pa.sender_power != pb.sender_power)
            {
                return pa.sender_power > pb.sender_power;
            }
            if (pa.origin_server_ts != pb.origin_server_ts)
            {
                return pa.origin_server_ts < pb.origin_server_ts;
            }
            // Spec (rooms/v10 — Reverse topological power ordering, rule 3):
            // final tie-break is the lexicographically smaller event_id.
            return a.event_id < b.event_id;
        }
    };

    // Build the mainline [P0, P1, …, Pn] of the resolved power_levels event:
    // P(i+1) is the m.room.power_levels event in Pi's auth_events, walked
    // transitively (spec rooms/v10 — Mainline ordering). The walk is bounded by
    // max_mainline_auth_chain_depth to prevent cyclic or adversarially deep
    // auth chains from consuming unbounded time/memory, and stops when an
    // ancestor's JSON is not available in the index.
    [[nodiscard]] auto collect_mainline_power_events(std::string const& head_event_id,
                                                     canonicaljson::Value const& power_levels_event,
                                                     EventJsonIndex const& events_by_id) -> std::vector<std::string>
    {
        auto result = std::vector<std::string>{};
        auto visited = std::unordered_set<std::string>{};

        auto current_id = head_event_id;
        auto const* current = value_is_object(power_levels_event);
        while (current != nullptr && result.size() < max_mainline_auth_chain_depth)
        {
            if (current_id.empty() || !visited.insert(current_id).second)
            {
                break;
            }
            result.push_back(current_id);

            auto const* ancestor_id = power_levels_auth_ancestor(*current, events_by_id);
            if (ancestor_id == nullptr)
            {
                break;
            }
            current_id = *ancestor_id;
            current = value_is_object(events_by_id.at(*ancestor_id).get());
        }
        return result;
    }

    [[nodiscard]] auto build_auth_event_map_from_state(canonicaljson::Value const& event, StateMap const& current_state)
        -> AuthEventMap
    {
        auto result = AuthEventMap{};
        auto const* obj = value_is_object(event);
        if (obj == nullptr)
        {
            return result;
        }
        auto const* event_type = string_member(*obj, "type");
        auto const* sender = string_member(*obj, "sender");
        auto const* state_key = string_member(*obj, "state_key");

        if (auto it = current_state.find(StateKey{"m.room.create", ""}); it != current_state.end())
        {
            result.create = it->second.event_json;
        }
        if (auto it = current_state.find(StateKey{"m.room.power_levels", ""}); it != current_state.end())
        {
            result.power_levels = it->second.event_json;
        }
        if (auto it = current_state.find(StateKey{"m.room.join_rules", ""}); it != current_state.end())
        {
            result.join_rules = it->second.event_json;
        }
        if (sender != nullptr)
        {
            if (auto it = current_state.find(StateKey{"m.room.member", *sender}); it != current_state.end())
            {
                result.sender_member = it->second.event_json;
            }
        }
        if (state_key != nullptr && event_type != nullptr && *event_type == "m.room.member")
        {
            if (auto it = current_state.find(StateKey{"m.room.member", *state_key}); it != current_state.end())
            {
                result.target_member = it->second.event_json;
            }

            // Spec: rooms/v11.md rule 4.3.1.5 — 3PID-token invites are authorized
            // against the m.room.third_party_invite event named by content's token.
            auto const* content = object_member_as_object(*obj, "content");
            auto const* third_party_invite =
                content == nullptr ? nullptr : object_member_as_object(*content, "third_party_invite");
            auto const* signed_obj =
                third_party_invite == nullptr ? nullptr : object_member_as_object(*third_party_invite, "signed");
            auto const* token = signed_obj == nullptr ? nullptr : string_member(*signed_obj, "token");
            if (token != nullptr)
            {
                if (auto it = current_state.find(StateKey{"m.room.third_party_invite", *token});
                    it != current_state.end())
                {
                    result.third_party_invite = it->second.event_json;
                }
            }
        }
        return result;
    }

} // namespace

auto state_key_matches(StateKey const& left, StateKey const& right) noexcept -> bool
{
    return left.event_type == right.event_type && left.state_key == right.state_key;
}

auto state_group_contains(StateGroup const& group, StateKey const& key) noexcept -> bool
{
    return state_group_event(group, key) != nullptr;
}

auto state_group_event(StateGroup const& group, StateKey const& key) noexcept -> StateEventReference const*
{
    for (auto const& event : group.state)
    {
        if (state_key_matches(event.key, key))
        {
            return &event;
        }
    }

    return nullptr;
}

// Validate request size against public resource caps. Returns an explicit error
// instead of starting the O(N log N) or O(N^2) work on an adversarial payload.
[[nodiscard]] auto validate_state_resolution_request(StateResolutionRequest const& request)
    -> std::optional<std::string>
{
    if (request.state_groups.size() > max_state_groups)
    {
        return "too many state groups";
    }

    for (auto const& group : request.state_groups)
    {
        if (group.state.size() > max_events_per_state_group)
        {
            return "too many events in state group";
        }
    }
    return std::nullopt;
}

auto resolve_state(StateResolutionRequest const& request) -> StateResolutionResult
{
    auto result = [&]() -> StateResolutionResult {
        if (request.room_version.empty())
        {
            return {false, {}, "room version is required"};
        }
        if (auto error = validate_state_resolution_request(request); error.has_value())
        {
            return {false, {}, *error};
        }
        if (request.state_groups.empty())
        {
            return {true, {}, {}};
        }

        auto resolved = StateMap{};
        for (auto const& group : request.state_groups)
        {
            for (auto const& event : group.state)
            {
                if (event.event_id.empty())
                {
                    return {false, {}, "state event id is required"};
                }

                auto const existing = resolved.find(event.key);
                if (existing == resolved.end())
                {
                    resolved.emplace(event.key, event);
                    continue;
                }
                if (existing->second.event_id == event.event_id)
                {
                    continue;
                }

                existing->second = select_v1_winner(existing->second, event);
            }
        }

        auto resolved_state = std::vector<StateEventReference>{};
        resolved_state.reserve(resolved.size());
        for (auto const& [key, event] : resolved)
        {
            resolved_state.push_back(event);
        }
        return {true, std::move(resolved_state), {}};
    }();
    log_diagnostic(result.resolved ? "resolve_state.resolved" : "resolve_state.failed",
                   {
                       {"room_version", request.room_version,                         false},
                       {"events",       std::to_string(result.resolved_state.size()), false},
                       {"reason",       result.reason,                                false}
    });
    return result;
}

auto partition_conflicted_state(std::vector<StateGroup> const& groups) -> std::pair<StateMap, StateMap>
{
    auto unconflicted = StateMap{};
    auto conflicted = StateMap{};
    auto counts = std::unordered_map<StateKey, int, StateKeyHash>{};
    counts.reserve(groups.size() * 8U);

    for (auto const& group : groups)
    {
        for (auto const& event : group.state)
        {
            counts[event.key]++;
            if (counts.size() > max_conflicted_state_keys)
            {
                // Fail fast: too many distinct state keys to resolve safely.
                return {};
            }
        }
    }

    auto total_groups = groups.size();

    for (auto const& group : groups)
    {
        for (auto const& event : group.state)
        {
            auto const count = counts[event.key];

            if (static_cast<std::size_t>(count) == total_groups)
            {
                auto const it = unconflicted.find(event.key);
                if (it == unconflicted.end())
                {
                    unconflicted[event.key] = event;
                }
                else if (it->second.event_id != event.event_id)
                {
                    auto moved = std::move(unconflicted.extract(event.key).mapped());
                    unconflicted.erase(event.key);
                    conflicted[event.key] = moved;
                    conflicted[event.key] = event;
                }
            }
            else
            {
                conflicted[event.key] = event;
            }
        }
    }

    return {unconflicted, conflicted};
}

auto reverse_topological_power_sort(std::vector<StateEventReference> const& conflicted, StateMap const& unconflicted)
    -> std::vector<StateEventReference>
{
    auto sorted = conflicted;
    std::stable_sort(sorted.begin(), sorted.end(), ReverseTopoCompare{unconflicted});
    return sorted;
}

auto is_power_event(StateEventReference const& event) noexcept -> bool
{
    if (event.key.event_type == "m.room.power_levels" || event.key.event_type == "m.room.join_rules")
    {
        return event.key.state_key.empty();
    }
    if (event.key.event_type != "m.room.member")
    {
        return false;
    }
    auto const* obj = value_is_object(event.event_json);
    if (obj == nullptr)
    {
        return false;
    }
    auto const* content = object_member_as_object(*obj, "content");
    if (content == nullptr)
    {
        return false;
    }
    auto const* membership = string_member(*content, "membership");
    if (membership == nullptr)
    {
        return false;
    }
    return (*membership == "leave" || *membership == "ban") && event.sender != event.key.state_key;
}

auto build_event_json_index(std::vector<StateGroup> const& groups) -> EventJsonIndex
{
    auto index = EventJsonIndex{};
    for (auto const& group : groups)
    {
        for (auto const& event : group.state)
        {
            if (!event.event_id.empty() && value_has_content(event.event_json))
            {
                index.emplace(event.event_id, std::cref(event.event_json));
            }
        }
    }
    return index;
}

auto mainline_order(std::vector<StateEventReference>& events, StateMap const& resolved,
                    EventJsonIndex const& events_by_id) -> void
{
    auto const pl_key = StateKey{"m.room.power_levels", ""};
    std::vector<std::string> mainline;

    auto it = resolved.find(pl_key);
    if (it != resolved.end() && value_has_content(it->second.event_json))
    {
        mainline = collect_mainline_power_events(it->second.event_id, it->second.event_json, events_by_id);
    }

    // If the mainline hit the depth cap, sorting by it would be misleading;
    // fall back to a timestamp ordering so we still terminate but do not
    // produce an ordering that depends on truncated data.
    auto const mainline_truncated = mainline.size() >= max_mainline_auth_chain_depth;

    auto mainline_depth = std::unordered_map<std::string, std::size_t>{};
    mainline_depth.reserve(mainline.size());
    for (std::size_t i = 0; i < mainline.size(); ++i)
    {
        mainline_depth[mainline[i]] = i;
    }

    // Spec (rooms/v10 — Mainline ordering): walk the event's power-levels
    // ancestry (e1, e2, …) until an event on the mainline is found; its
    // mainline index is the event's position. If the walk exhausts without
    // reaching the mainline, the position is ∞ — a sentinel greater than any
    // index — so the event sorts as oldest.
    auto const infinity = std::numeric_limits<std::size_t>::max();
    auto mainline_position = [&](StateEventReference const& event) -> std::size_t {
        auto visited = std::unordered_set<std::string>{};
        auto const* current = value_is_object(event.event_json);
        for (std::size_t hops = 0; current != nullptr && hops < max_mainline_auth_chain_depth; ++hops)
        {
            auto const* auth = array_member(*current, "auth_events");
            if (auth == nullptr)
            {
                return infinity;
            }
            // A mainline hit among the auth entries wins immediately: every
            // mainline entry is a power_levels event, and a valid event cites
            // at most one power_levels event in its auth_events.
            for (auto const& entry : *auth)
            {
                auto const* id = auth_entry_event_id(entry);
                if (id == nullptr)
                {
                    continue;
                }
                if (auto dit = mainline_depth.find(*id); dit != mainline_depth.end())
                {
                    return dit->second;
                }
            }
            auto const* ancestor_id = power_levels_auth_ancestor(*current, events_by_id);
            if (ancestor_id == nullptr || !visited.insert(*ancestor_id).second)
            {
                return infinity;
            }
            current = value_is_object(events_by_id.at(*ancestor_id).get());
        }
        return infinity;
    };

    auto position_by_event_id = std::unordered_map<std::string, std::size_t>{};
    position_by_event_id.reserve(events.size());
    for (auto const& event : events)
    {
        position_by_event_id.emplace(event.event_id, mainline_truncated ? infinity : mainline_position(event));
    }

    auto mainline_compare = [&position_by_event_id](StateEventReference const& a,
                                                    StateEventReference const& b) -> bool {
        auto const pos_a = position_by_event_id.at(a.event_id);
        auto const pos_b = position_by_event_id.at(b.event_id);
        if (pos_a != pos_b)
        {
            // Spec: x < y when x's mainline position is GREATER than y's
            // (an auth chain based on an earlier mainline event sorts first).
            return pos_a > pos_b;
        }
        if (a.origin_server_ts != b.origin_server_ts)
        {
            return a.origin_server_ts < b.origin_server_ts;
        }
        return a.event_id < b.event_id;
    };

    std::stable_sort(events.begin(), events.end(), mainline_compare);
}

auto resolve_state_v2(StateResolutionRequest const& request, rooms::RoomVersionPolicy const& policy)
    -> StateResolutionResult
{
    if (auto error = validate_state_resolution_request(request); error.has_value())
    {
        log_diagnostic("resolve_state_v2.rejected",
                       {
                           {"room_version", request.room_version, false},
                           {"reason",       *error,               false}
        });
        return {false, {}, *error};
    }

    if (request.state_groups.empty())
    {
        log_diagnostic("resolve_state_v2.empty", {
                                                     {"room_version", request.room_version, false}
        });
        return {true, {}, {}};
    }

    // Step 1: Partition into conflicted and unconflicted
    auto [unconflicted, conflicted_events] = partition_conflicted_state(request.state_groups);

    // Step 2: Start from unconflicted state
    auto resolved = unconflicted;

    // Step 3: Collect all conflicted events and sort by reverse topological power ordering
    if (unconflicted.empty() && conflicted_events.empty())
    {
        // partition_conflicted_state aborted because there were too many
        // distinct state keys to process safely.
        log_diagnostic("resolve_state_v2.rejected",
                       {
                           {"room_version", request.room_version,  false},
                           {"reason",       "too many state keys", false}
        });
        return {false, {}, "too many state keys"};
    }

    auto all_conflicted = std::vector<StateEventReference>{};
    all_conflicted.reserve(conflicted_events.size());
    for (auto const& group : request.state_groups)
    {
        for (auto const& event : group.state)
        {
            if (!conflicted_events.contains(event.key))
            {
                continue;
            }

            auto const duplicate = std::ranges::any_of(all_conflicted, [&event](StateEventReference const& existing) {
                return state_key_matches(existing.key, event.key) && existing.event_id == event.event_id;
            });
            if (!duplicate)
            {
                all_conflicted.push_back(event);
                if (all_conflicted.size() > max_conflicted_state_keys)
                {
                    log_diagnostic("resolve_state_v2.rejected", {
                                                                    {"room_version", request.room_version,         false},
                                                                    {"reason",       "too many conflicted events", false}
                    });
                    return {false, {}, "too many conflicted events"};
                }
            }
        }
    }

    // Iterative auth checks (spec rooms/v10 — Algorithm): apply each event to
    // the running resolved state if it passes the authorization rules. All
    // candidates for each key must be iterated — a later (lower-power)
    // candidate can still overwrite an earlier one if it passes auth. Do NOT
    // short-circuit on resolved.contains(key).
    auto apply_iterative_auth_checks = [&resolved, &policy](std::vector<StateEventReference> const& sorted) -> void {
        for (auto const& event : sorted)
        {
            // Events whose JSON representation is null/invalid cannot be applied.
            if (!value_has_content(event.event_json))
            {
                continue;
            }

            auto auth_map = build_auth_event_map_from_state(event.event_json, resolved);
            auto const decision = authorize_event_against_auth_events(event.event_json, policy, auth_map);
            if (decision.allowed)
            {
                resolved[event.key] = event;
            }
        }
    };

    // Algorithm step 1: select the power events from the conflicted set and
    // sort them by the reverse topological power ordering.
    auto power_events = std::vector<StateEventReference>{};
    auto remaining_events = std::vector<StateEventReference>{};
    for (auto const& event : all_conflicted)
    {
        if (is_power_event(event))
        {
            power_events.push_back(event);
        }
        else
        {
            remaining_events.push_back(event);
        }
    }
    auto const sorted_power = reverse_topological_power_sort(power_events, unconflicted);

    // Algorithm step 2: auth-check the power events first, starting from the
    // unconflicted state, to obtain the partially resolved state.
    apply_iterative_auth_checks(sorted_power);

    // Algorithm step 3: order only the remaining (non-power) events by the
    // mainline ordering based on the power levels in the partially resolved
    // state.
    auto const events_by_id = build_event_json_index(request.state_groups);
    mainline_order(remaining_events, resolved, events_by_id);

    // Algorithm step 4: auth-check the remaining events against the partially
    // resolved state. (Step 5 — reapplying the unconflicted map — is a no-op
    // here because unconflicted and conflicted keys are disjoint by
    // construction.)
    apply_iterative_auth_checks(remaining_events);

    // Build result
    auto result_state = std::vector<StateEventReference>{};
    for (auto const& [key, event] : resolved)
    {
        result_state.push_back(event);
    }

    log_diagnostic("resolve_state_v2.resolved", {
                                                    {"room_version", request.room_version,                false},
                                                    {"events",       std::to_string(result_state.size()), false}
    });
    return {true, std::move(result_state), {}};
}

auto state_resolution_summary(StateResolutionResult const& result) -> std::string
{
    return "state resolution: resolved=" + std::string{result.resolved ? "true" : "false"} +
           " events=" + std::to_string(result.resolved_state.size()) + " reason=" + result.reason;
}

} // namespace merovingian::events
