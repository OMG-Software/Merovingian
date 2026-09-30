// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/history_visibility.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/canonicaljson/value.hpp"
#include "merovingian/events/limits.hpp"

#include <algorithm>
#include <string>
#include <unordered_set>
#include <utility>
#include <variant>

namespace merovingian::sync
{

namespace
{

    constexpr auto history_visibility_type = std::string_view{"m.room.history_visibility"};
    constexpr auto member_type = std::string_view{"m.room.member"};

    // The string at `content.<key>` of a stored event's JSON.
    [[nodiscard]] auto content_string_of(std::string_view event_json,
                                         std::string_view key) -> std::optional<std::string>
    {
        auto const parsed = canonicaljson::parse_lossless(event_json);
        if (parsed.error != canonicaljson::ParseError::none)
        {
            return std::nullopt;
        }
        auto const* event = std::get_if<canonicaljson::Object>(&parsed.value.storage());
        if (event == nullptr)
        {
            return std::nullopt;
        }
        for (auto const& member : *event)
        {
            if (member.key != "content")
            {
                continue;
            }
            auto const* content = std::get_if<canonicaljson::Object>(&member.value->storage());
            if (content == nullptr)
            {
                return std::nullopt;
            }
            for (auto const& field : *content)
            {
                if (field.key == key)
                {
                    auto const* text = std::get_if<std::string>(&field.value->storage());
                    return text == nullptr ? std::nullopt : std::optional<std::string>{*text};
                }
            }
            return std::nullopt;
        }
        return std::nullopt;
    }

    [[nodiscard]] auto event_is_withheld(database::PersistentEvent const& event) noexcept -> bool
    {
        // ADR-0064 phase B2: a rejected or soft-failed event is never relayed to clients.
        return event.status == "rejected" || event.status == "soft_failed";
    }

} // namespace

auto parse_history_visibility(std::string_view value) noexcept -> HistoryVisibilityValue
{
    if (value == "world_readable")
    {
        return HistoryVisibilityValue::world_readable;
    }
    if (value == "invited")
    {
        return HistoryVisibilityValue::invited;
    }
    if (value == "joined")
    {
        return HistoryVisibilityValue::joined;
    }
    return HistoryVisibilityValue::shared;
}

auto current_history_visibility(database::PersistentStore const& store,
                                std::string_view room_id) -> HistoryVisibilityValue
{
    for (auto const& state : store.state)
    {
        if (state.room_id != room_id || state.event_type != history_visibility_type || !state.state_key.empty())
        {
            continue;
        }
        for (auto const& event : store.events)
        {
            if (event.event_id == state.event_id)
            {
                auto const value = content_string_of(event.json, "history_visibility");
                return value.has_value() ? parse_history_visibility(*value) : HistoryVisibilityValue::shared;
            }
        }
        return HistoryVisibilityValue::shared;
    }
    return HistoryVisibilityValue::shared;
}

auto room_is_world_readable(database::PersistentStore const& store, std::string_view room_id) -> bool
{
    return current_history_visibility(store, room_id) == HistoryVisibilityValue::world_readable;
}

HistoryVisibility::HistoryVisibility(database::PersistentStore const& store, std::string_view user_id)
    : store_{store}
    , user_id_{user_id}
{
}

auto HistoryVisibility::ensure_event_index() -> void
{
    if (event_index_built_)
    {
        return;
    }
    events_by_id_.reserve(store_.events.size());
    for (auto const& event : store_.events)
    {
        events_by_id_.emplace(event.event_id, &event);
    }
    event_index_built_ = true;
}

auto HistoryVisibility::ensure_event_group_index() -> void
{
    if (event_group_index_built_)
    {
        return;
    }
    group_by_event_.reserve(store_.event_state_groups.size());
    for (auto const& mapping : store_.event_state_groups)
    {
        group_by_event_.emplace(mapping.event_id, mapping.state_group_id);
    }
    event_group_index_built_ = true;
}

auto HistoryVisibility::ensure_group_index() -> void
{
    if (group_index_built_)
    {
        return;
    }
    groups_by_id_.reserve(store_.state_groups.size());
    for (auto const& group : store_.state_groups)
    {
        groups_by_id_.emplace(group.state_group_id, &group);
    }
    for (auto const& entry : store_.state_group_state)
    {
        entries_by_group_[entry.state_group_id].push_back(&entry);
    }
    group_index_built_ = true;
}

auto HistoryVisibility::find_event(std::string_view event_id) -> database::PersistentEvent const*
{
    ensure_event_index();
    auto const found = events_by_id_.find(event_id);
    return found == events_by_id_.end() ? nullptr : found->second;
}

auto HistoryVisibility::state_group_of(std::string_view event_id) -> std::optional<std::string_view>
{
    ensure_event_group_index();
    auto const found = group_by_event_.find(event_id);
    return found == group_by_event_.end() ? std::nullopt : std::optional<std::string_view>{found->second};
}

// Finds the event ID that `group_id`'s full state holds for (event_type, state_key), walking
// the delta chain newest first exactly as database::read_state_group_full_state does: bounded,
// cycle-checked, and broken (not "absent") when a group on the chain is missing.
auto HistoryVisibility::lookup_in_group(std::string_view group_id, std::string_view event_type,
                                        std::string_view state_key) -> LookupResult
{
    ensure_group_index();
    auto visited = std::unordered_set<std::string_view>{};
    auto current = group_id;
    for (auto hops = std::size_t{0U};; ++hops)
    {
        if (!visited.insert(current).second || hops > events::max_state_group_delta_depth)
        {
            return {Lookup::broken, {}};
        }
        auto const group = groups_by_id_.find(current);
        if (group == groups_by_id_.end())
        {
            return {Lookup::broken, {}};
        }
        if (auto const entries = entries_by_group_.find(current); entries != entries_by_group_.end())
        {
            for (auto const* entry : entries->second)
            {
                if (entry->event_type == event_type && entry->state_key == state_key)
                {
                    return {Lookup::found, entry->event_id};
                }
            }
        }
        if (!group->second->parent_state_group_id.has_value())
        {
            return {Lookup::absent, {}};
        }
        current = *group->second->parent_state_group_id;
    }
}

auto HistoryVisibility::content_string(std::string_view event_id, std::string_view key) -> std::optional<std::string>
{
    auto cache_key = std::string{event_id};
    cache_key.push_back('\0');
    cache_key.append(key);
    if (auto const cached = content_cache_.find(cache_key); cached != content_cache_.end())
    {
        return cached->second;
    }
    auto const* event = find_event(event_id);
    auto value = event == nullptr ? std::nullopt : content_string_of(event->json, key);
    content_cache_.emplace(std::move(cache_key), value);
    return value;
}

auto HistoryVisibility::view_of_group(std::string_view group_id) -> GroupView const&
{
    auto const key = std::string{group_id};
    if (auto const cached = group_views_.find(key); cached != group_views_.end())
    {
        return cached->second;
    }
    auto view = GroupView{};
    auto const visibility_event = lookup_in_group(group_id, history_visibility_type, "");
    auto const member_event = lookup_in_group(group_id, member_type, user_id_);
    if (visibility_event.outcome != Lookup::broken && member_event.outcome != Lookup::broken)
    {
        view.valid = true;
        if (visibility_event.outcome == Lookup::found)
        {
            if (find_event(visibility_event.event_id) == nullptr)
            {
                view.valid = false; // the group names an event this store does not hold
            }
            else if (auto const value = content_string(visibility_event.event_id, "history_visibility");
                     value.has_value())
            {
                view.visibility = parse_history_visibility(*value);
            }
        }
        if (view.valid && member_event.outcome == Lookup::found)
        {
            if (find_event(member_event.event_id) == nullptr)
            {
                view.valid = false;
            }
            else if (auto const value = content_string(member_event.event_id, "membership"); value.has_value())
            {
                view.membership = *value;
            }
        }
    }
    return group_views_.emplace(key, std::move(view)).first->second;
}

// The stream ordering of the newest accepted `join` event of the user in `room_id`. Every
// `m.room.member` event of the user that was ever part of a room's state is named by some
// state group row (or by the current state), so scanning those rows finds them without parsing
// the room's events.
auto HistoryVisibility::max_join_ordering(std::string_view room_id) -> std::optional<std::uint64_t>
{
    auto const key = std::string{room_id};
    if (auto const cached = join_orderings_.find(key); cached != join_orderings_.end())
    {
        return cached->second;
    }
    auto candidates = std::unordered_set<std::string_view>{};
    for (auto const& entry : store_.state_group_state)
    {
        if (entry.event_type == member_type && entry.state_key == user_id_)
        {
            candidates.insert(entry.event_id);
        }
    }
    for (auto const& state : store_.state)
    {
        if (state.room_id == room_id && state.event_type == member_type && state.state_key == user_id_)
        {
            candidates.insert(state.event_id);
        }
    }
    auto newest = std::optional<std::uint64_t>{};
    for (auto const candidate : candidates)
    {
        auto const* event = find_event(candidate);
        if (event == nullptr || event->room_id != room_id || event_is_withheld(*event))
        {
            continue;
        }
        if (content_string(candidate, "membership") == std::optional<std::string>{"join"} &&
            (!newest.has_value() || event->stream_ordering > *newest))
        {
            newest = event->stream_ordering;
        }
    }
    join_orderings_.emplace(key, newest);
    return newest;
}

// The chain of the user's m.room.member events, walked back from their current one through the
// recorded predecessors. A user with no member state at all has an empty (determined) timeline.
// A missing event, a cycle or a chain past the bound is undeterminable.
auto HistoryVisibility::membership_timeline(std::string_view room_id)
    -> std::optional<std::vector<MembershipStep>> const&
{
    auto const key = std::string{room_id};
    if (auto const cached = membership_timelines_.find(key); cached != membership_timelines_.end())
    {
        return cached->second;
    }
    auto timeline = std::optional<std::vector<MembershipStep>>{std::vector<MembershipStep>{}};
    auto current = std::string_view{};
    for (auto const& state : store_.state)
    {
        if (state.room_id == room_id && state.event_type == member_type && state.state_key == user_id_)
        {
            current = state.event_id;
            break;
        }
    }
    constexpr auto max_chain = std::size_t{4096U};
    auto steps = std::size_t{0U};
    while (!current.empty())
    {
        auto const* event = find_event(current);
        if (event == nullptr || event->room_id != room_id || ++steps > max_chain)
        {
            timeline = std::nullopt;
            break;
        }
        if (!event_is_withheld(*event))
        {
            auto const membership = content_string(current, "membership");
            if (!membership.has_value())
            {
                timeline = std::nullopt;
                break;
            }
            timeline->push_back({event->stream_ordering, *membership});
        }
        auto const* transition = database::find_state_transition(store_, room_id, member_type, user_id_, current);
        if (transition == nullptr)
        {
            break;
        }
        current = transition->previous_event_id;
    }
    if (timeline.has_value())
    {
        std::ranges::sort(*timeline, {}, &MembershipStep::ordering);
    }
    return membership_timelines_.emplace(key, std::move(timeline)).first->second;
}

auto HistoryVisibility::joined_when_sent(database::PersistentEvent const& event) -> bool
{
    auto const& timeline = membership_timeline(event.room_id);
    if (!timeline.has_value())
    {
        return false;
    }
    auto latest = std::string_view{};
    for (auto const& step : *timeline)
    {
        if (step.ordering > event.stream_ordering)
        {
            break;
        }
        latest = step.membership;
    }
    return latest == "join";
}

auto HistoryVisibility::allows(HistoryVisibilityValue visibility, std::string_view membership,
                               database::PersistentEvent const& event) -> bool
{
    if (visibility == HistoryVisibilityValue::world_readable)
    {
        return true; // rule 1
    }
    if (membership == "join")
    {
        return true; // rule 2
    }
    if (visibility == HistoryVisibilityValue::shared)
    {
        // Rule 3: the user joined the room at any point after the event was sent.
        auto const joined = max_join_ordering(event.room_id);
        return joined.has_value() && *joined > event.stream_ordering;
    }
    // Rule 4; rule 5 (deny) otherwise.
    return membership == "invite" && visibility == HistoryVisibilityValue::invited;
}

auto HistoryVisibility::can_see(database::PersistentEvent const& event) -> bool
{
    if (event_is_withheld(event))
    {
        return false;
    }
    auto const group_id = state_group_of(event.event_id);
    if (!group_id.has_value())
    {
        // No recorded state (history from before ADR-0064): the visibility at the time cannot
        // be proved, so only rule 2 applies, judged from the user's own membership timeline.
        return joined_when_sent(event);
    }
    auto const& view = view_of_group(*group_id);
    if (!view.valid)
    {
        return false;
    }
    if (allows(view.visibility, view.membership, event))
    {
        return true;
    }

    // Special case: a history_visibility event is visible when the visibility BEFORE it
    // would have allowed the user to see it. The predecessor is the event it replaced.
    if (auto const* transition =
            database::find_state_transition(store_, event.room_id, history_visibility_type, "", event.event_id);
        transition != nullptr)
    {
        auto before = HistoryVisibilityValue::shared; // no earlier event: the default
        auto known = true;
        if (!transition->previous_event_id.empty())
        {
            if (find_event(transition->previous_event_id) == nullptr)
            {
                known = false;
            }
            else if (auto const value = content_string(transition->previous_event_id, "history_visibility");
                     value.has_value())
            {
                before = parse_history_visibility(*value);
            }
        }
        if (known && allows(before, view.membership, event))
        {
            return true;
        }
    }

    // Special case: the user's own m.room.member event is visible when their membership
    // BEFORE it would have allowed them to see it.
    if (auto const* transition =
            database::find_state_transition(store_, event.room_id, member_type, user_id_, event.event_id);
        transition != nullptr)
    {
        auto membership_before = std::string{};
        auto known = true;
        if (!transition->previous_event_id.empty())
        {
            if (find_event(transition->previous_event_id) == nullptr)
            {
                known = false;
            }
            else if (auto const value = content_string(transition->previous_event_id, "membership"); value.has_value())
            {
                membership_before = *value;
            }
        }
        if (known && allows(view.visibility, membership_before, event))
        {
            return true;
        }
    }
    return false;
}

auto HistoryVisibility::can_see_event_id(std::string_view event_id) -> bool
{
    auto const* event = find_event(event_id);
    return event != nullptr && can_see(*event);
}

} // namespace merovingian::sync
