// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <string_view>
#include <vector>

namespace merovingian::events
{

struct StateKey final
{
    std::string event_type{};
    std::string state_key{};
};

struct StateEventReference final
{
    StateKey key{};
    std::string event_id{};
    std::string sender{};
};

struct StateGroup final
{
    std::string group_id{};
    std::vector<StateEventReference> state{};
};

struct StateResolutionRequest final
{
    std::string room_version{};
    std::vector<StateGroup> state_groups{};
};

struct StateResolutionResult final
{
    bool resolved{false};
    std::vector<StateEventReference> resolved_state{};
    std::string reason{};
};

[[nodiscard]] auto state_key_matches(StateKey const& left, StateKey const& right) noexcept -> bool;
[[nodiscard]] auto state_group_contains(StateGroup const& group, StateKey const& key) noexcept -> bool;
[[nodiscard]] auto state_group_event(StateGroup const& group, StateKey const& key) noexcept
    -> StateEventReference const*;
[[nodiscard]] auto resolve_state(StateResolutionRequest const& request) -> StateResolutionResult;
[[nodiscard]] auto state_resolution_summary(StateResolutionResult const& result) -> std::string;

} // namespace merovingian::events
