// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/events/state_resolution.hpp"

#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/events/authorization.hpp"
#include "merovingian/rooms/room_version_policy.hpp"

#include <algorithm>
#include <cstdint>
#include <string>
#include <utility>
#include <variant>

namespace merovingian::events
{
namespace
{

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

    [[nodiscard]] auto value_has_content(canonicaljson::Value const& value) noexcept -> bool
    {
        return !std::holds_alternative<std::nullptr_t>(value.storage());
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
            return pa.origin_server_ts < pb.origin_server_ts;
        }
    };

    [[nodiscard]] auto collect_mainline_power_events(canonicaljson::Value const& power_levels_event)
        -> std::vector<std::string>
    {
        auto result = std::vector<std::string>{};
        // Walk the auth_events chain of the power_levels event to find the mainline
        // For v2, mainline = the power_levels auth chain
        // Simplified: extract from the event's own prev auth_events references
        // For now, we just use the power_levels event itself as the mainline head
        auto const* obj = value_is_object(power_levels_event);
        if (obj == nullptr)
        {
            return result;
        }
        auto const* event_id = string_member(*obj, "event_id");
        if (event_id != nullptr)
        {
            result.push_back(*event_id);
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

auto resolve_state(StateResolutionRequest const& request) -> StateResolutionResult
{
    if (request.room_version.empty())
    {
        return {false, {}, "room version is required"};
    }
    if (request.state_groups.empty())
    {
        return {true, {}, {}};
    }

    auto result = StateResolutionResult{true, {}, {}};
    for (auto const& group : request.state_groups)
    {
        for (auto const& event : group.state)
        {
            if (event.event_id.empty())
            {
                return {false, {}, "state event id is required"};
            }

            auto const* existing = [&]() -> StateEventReference const* {
                for (auto const& resolved : result.resolved_state)
                {
                    if (state_key_matches(resolved.key, event.key))
                    {
                        return &resolved;
                    }
                }
                return nullptr;
            }();

            if (existing == nullptr)
            {
                result.resolved_state.push_back(event);
                continue;
            }
            if (existing->event_id != event.event_id)
            {
                return {false, result.resolved_state, "conflicting state requires full resolution"};
            }
        }
    }

    return result;
}

auto partition_conflicted_state(std::vector<StateGroup> const& groups) -> std::pair<StateMap, StateMap>
{
    auto unconflicted = StateMap{};
    auto conflicted = StateMap{};
    auto counts = std::unordered_map<StateKey, int, StateKeyHash>{};

    for (auto const& group : groups)
    {
        for (auto const& event : group.state)
        {
            counts[event.key]++;
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

auto mainline_order(std::vector<StateEventReference>& events, StateMap const& unconflicted) -> void
{
    auto const pl_key = StateKey{"m.room.power_levels", ""};
    std::vector<std::string> mainline;

    auto it = unconflicted.find(pl_key);
    if (it != unconflicted.end() && value_has_content(it->second.event_json))
    {
        mainline = collect_mainline_power_events(it->second.event_json);
    }
    for (auto const& ev : events)
    {
        if (ev.key == pl_key && value_has_content(ev.event_json))
        {
            auto ev_mainline = collect_mainline_power_events(ev.event_json);
            for (auto const& id : ev_mainline)
            {
                if (std::find(mainline.begin(), mainline.end(), id) == mainline.end())
                {
                    mainline.push_back(id);
                }
            }
        }
    }

    auto mainline_depth = std::unordered_map<std::string, std::size_t>{};
    for (std::size_t i = 0; i < mainline.size(); ++i)
    {
        mainline_depth[mainline[i]] = i;
    }

    auto mainline_compare = [&mainline_depth](StateEventReference const& a, StateEventReference const& b) -> bool {
        auto depth_a = std::size_t{0};
        auto depth_b = std::size_t{0};

        auto const* obj_a = value_is_object(a.event_json);
        if (obj_a != nullptr)
        {
            auto const* auth_a = object_member_as_object(*obj_a, "auth_events");
            if (auth_a != nullptr)
            {
                for (auto const& member : *auth_a)
                {
                    auto const* id = std::get_if<std::string>(&member.value->storage());
                    if (id != nullptr)
                    {
                        auto dit = mainline_depth.find(*id);
                        if (dit != mainline_depth.end())
                        {
                            depth_a = dit->second;
                            break;
                        }
                    }
                }
            }
        }

        auto const* obj_b = value_is_object(b.event_json);
        if (obj_b != nullptr)
        {
            auto const* auth_b = object_member_as_object(*obj_b, "auth_events");
            if (auth_b != nullptr)
            {
                for (auto const& member : *auth_b)
                {
                    auto const* id = std::get_if<std::string>(&member.value->storage());
                    if (id != nullptr)
                    {
                        auto dit = mainline_depth.find(*id);
                        if (dit != mainline_depth.end())
                        {
                            depth_b = dit->second;
                            break;
                        }
                    }
                }
            }
        }

        if (depth_a != depth_b)
        {
            return depth_a > depth_b;
        }
        return a.origin_server_ts < b.origin_server_ts;
    };

    std::stable_sort(events.begin(), events.end(), mainline_compare);
}

auto resolve_state_v2(StateResolutionRequest const& request, rooms::RoomVersionPolicy const& policy)
    -> StateResolutionResult
{
    if (request.state_groups.empty())
    {
        return {true, {}, {}};
    }

    // Step 1: Partition into conflicted and unconflicted
    auto [unconflicted, conflicted_events] = partition_conflicted_state(request.state_groups);

    // Step 2: Start from unconflicted state
    auto resolved = unconflicted;

    // Step 3: Collect all conflicted events and sort by reverse topological power ordering
    auto all_conflicted = std::vector<StateEventReference>{};
    for (auto const& [key, event] : conflicted_events)
    {
        all_conflicted.push_back(event);
    }

    auto sorted = reverse_topological_power_sort(all_conflicted, unconflicted);

    // Step 4: Apply mainline ordering for power_levels events
    mainline_order(sorted, unconflicted);

    // Step 5: Iterate through sorted conflicted events, auth-check each against current resolved state
    for (auto const& event : sorted)
    {
        auto auth_map = build_auth_event_map_from_state(event.event_json, resolved);
        if (!value_has_content(event.event_json))
        {
            continue;
        }
        auto const decision = authorize_event_against_auth_events(event.event_json, policy, auth_map);
        if (decision.allowed)
        {
            resolved[event.key] = event;
        }
    }

    // Build result
    auto result_state = std::vector<StateEventReference>{};
    for (auto const& [key, event] : resolved)
    {
        result_state.push_back(event);
    }

    return {true, std::move(result_state), {}};
}

auto state_resolution_summary(StateResolutionResult const& result) -> std::string
{
    return "state resolution: resolved=" + std::string{result.resolved ? "true" : "false"} +
           " events=" + std::to_string(result.resolved_state.size()) + " reason=" + result.reason;
}

} // namespace merovingian::events