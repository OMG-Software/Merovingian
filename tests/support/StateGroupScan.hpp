// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStateGroup.hpp"
#include "merovingian/database/PersistentStateGroupStateEntry.hpp"
#include "merovingian/database/PersistentStore.hpp"

#include <algorithm>
#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace merovingian::tests
{

// Answers the three state-group lookups the way the vectors they replaced did (ADR-0325): a linear
// pass over the table's rows. A test compares these with the store's indexed lookups to show the
// index agrees with the rows after a write, a reload or a hydration.

[[nodiscard]] inline auto scanned_event_group(database::PersistentStore const& store, std::string_view event_id)
    -> std::optional<std::string>
{
    for (auto const& mapping : store.event_state_groups)
    {
        if (mapping.event_id == event_id)
        {
            return mapping.state_group_id;
        }
    }
    return std::nullopt;
}

[[nodiscard]] inline auto scanned_group_entries(database::PersistentStore const& store, std::string_view group_id)
    -> std::vector<database::PersistentStateGroupStateEntry>
{
    auto entries = std::vector<database::PersistentStateGroupStateEntry>{};
    for (auto const& entry : store.state_group_state)
    {
        if (entry.state_group_id == group_id)
        {
            entries.push_back(entry);
        }
    }
    return entries;
}

[[nodiscard]] inline auto scanned_group(database::PersistentStore const& store, std::string_view group_id)
    -> std::optional<database::PersistentStateGroup>
{
    for (auto const& group : store.state_groups)
    {
        if (group.state_group_id == group_id)
        {
            return group;
        }
    }
    return std::nullopt;
}

// Empty when every indexed lookup agrees with a scan, for every row the tables hold and for a key
// they do not; otherwise a description of the first disagreement.
[[nodiscard]] inline auto state_group_index_mismatch(database::PersistentStore const& store) -> std::string
{
    for (auto const& mapping : store.event_state_groups)
    {
        if (database::find_event_state_group(store, mapping.event_id) != scanned_event_group(store, mapping.event_id))
        {
            return "event group of " + mapping.event_id;
        }
    }
    if (database::find_event_state_group(store, "$not-an-event").has_value())
    {
        return "event group of an absent event";
    }
    auto group_ids = std::unordered_set<std::string>{};
    for (auto const& group : store.state_groups)
    {
        group_ids.insert(group.state_group_id);
    }
    for (auto const& entry : store.state_group_state)
    {
        group_ids.insert(entry.state_group_id);
    }
    for (auto const& group_id : group_ids)
    {
        auto const found = database::find_state_group(store, group_id);
        auto const scanned = scanned_group(store, group_id);
        if (found.has_value() != scanned.has_value() ||
            (found.has_value() &&
             (found->room_id != scanned->room_id || found->parent_state_group_id != scanned->parent_state_group_id ||
              found->delta_depth != scanned->delta_depth)))
        {
            return "group " + group_id;
        }
        auto const scanned_entries = scanned_group_entries(store, group_id);
        auto indexed_entries = std::vector<database::PersistentStateGroupStateEntry>{};
        for (auto const& entry : store.state_group_state.entries_of(group_id))
        {
            indexed_entries.push_back(entry);
        }
        if (indexed_entries.size() != scanned_entries.size() ||
            store.state_group_state.count_of(group_id) != scanned_entries.size() ||
            !std::ranges::equal(indexed_entries, scanned_entries, [](auto const& a, auto const& b) {
                return a.event_type == b.event_type && a.state_key == b.state_key && a.event_id == b.event_id;
            }))
        {
            return "entries of " + group_id;
        }
    }
    if (store.state_groups.contains("sg:not-a-group") || store.state_group_state.count_of("sg:not-a-group") != 0U)
    {
        return "an absent group";
    }
    return {};
}

} // namespace merovingian::tests
