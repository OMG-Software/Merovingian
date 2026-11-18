// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/sync/ResolvedState.hpp"

#include "merovingian/database/PersistentStateEvent.hpp"
#include "merovingian/database/StateChangeLog.hpp"

#include <map>
#include <utility>

namespace merovingian::sync
{

namespace
{

    using StateKey = std::pair<std::string, std::string>;

    // What one key held at `since` and, when it changed again after `position`, at `position`.
    struct KeyValues final
    {
        std::string at_since{};
        std::optional<std::string> at_position{};
    };

} // namespace

auto resolved_state_at(database::PersistentStore const& store, std::string_view room_id, std::uint64_t position)
    -> std::optional<std::vector<std::string>>
{
    auto const& log = store.state_change_log;
    if (!log.covers(room_id, position))
    {
        return std::nullopt;
    }
    // The value each key changed above `position` held then: the one its first such change replaced.
    auto restored = std::map<StateKey, std::string>{};
    for (auto const* change : log.changes_after(room_id, position))
    {
        restored.try_emplace(StateKey{change->event_type, change->state_key}, change->previous_event_id);
    }
    auto ids = std::vector<std::string>{};
    database::for_each_room_state_row(store, room_id, [&](database::PersistentStateEvent const& row) {
        auto const found = restored.find(StateKey{row.event_type, row.state_key});
        if (found == restored.end())
        {
            ids.push_back(row.event_id);
            return;
        }
        if (!found->second.empty())
        {
            ids.push_back(found->second);
        }
        restored.erase(found);
    });
    // Keys removed from the current state since, which held a value at `position`.
    for (auto& [key, event_id] : restored)
    {
        if (!event_id.empty())
        {
            ids.push_back(std::move(event_id));
        }
    }
    return ids;
}

auto resolved_state_event_at(database::PersistentStore const& store, std::string_view room_id,
                             std::string_view event_type, std::string_view state_key, std::uint64_t position)
    -> std::optional<std::string>
{
    auto const& log = store.state_change_log;
    if (!log.covers(room_id, position))
    {
        return std::nullopt;
    }
    for (auto const* change : log.changes_after(room_id, position))
    {
        if (change->event_type == event_type && change->state_key == state_key)
        {
            return change->previous_event_id;
        }
    }
    return database::find_current_state_event_id(store, room_id, event_type, state_key).value_or(std::string{});
}

auto resolved_state_changes(database::PersistentStore const& store, std::string_view room_id, std::uint64_t since,
                            std::uint64_t position) -> std::optional<std::vector<std::string>>
{
    auto const& log = store.state_change_log;
    if (!log.covers(room_id, since))
    {
        return std::nullopt;
    }
    auto ids = std::vector<std::string>{};
    if (position <= since)
    {
        return ids;
    }
    auto keys = std::map<StateKey, KeyValues>{};
    for (auto const* change : log.changes_after(room_id, since))
    {
        auto const [entry, first] = keys.try_emplace(StateKey{change->event_type, change->state_key});
        if (first)
        {
            entry->second.at_since = change->previous_event_id;
        }
        if (change->position > position && !entry->second.at_position.has_value())
        {
            entry->second.at_position = change->previous_event_id;
        }
    }
    for (auto const& [key, values] : keys)
    {
        auto const at_position =
            values.at_position.has_value()
                ? *values.at_position
                : database::find_current_state_event_id(store, room_id, key.first, key.second).value_or(std::string{});
        // A key with no value at `position` cannot be sent: `state_after` has no way to remove one.
        if (!at_position.empty() && at_position != values.at_since)
        {
            ids.push_back(at_position);
        }
    }
    return ids;
}

} // namespace merovingian::sync
