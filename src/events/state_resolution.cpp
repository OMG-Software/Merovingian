// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/events/state_resolution.hpp"

#include <string>

namespace merovingian::events
{
namespace
{

    [[nodiscard]] auto resolved_event(std::vector<StateEventReference> const& state, StateKey const& key) noexcept
        -> StateEventReference const*
    {
        for (auto const& event : state)
        {
            if (state_key_matches(event.key, key))
            {
                return &event;
            }
        }

        return nullptr;
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

            auto const* existing = resolved_event(result.resolved_state, event.key);
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

auto state_resolution_summary(StateResolutionResult const& result) -> std::string
{
    return "state resolution: resolved=" + std::string{result.resolved ? "true" : "false"} +
           " events=" + std::to_string(result.resolved_state.size()) + " reason=" + result.reason;
}

} // namespace merovingian::events
