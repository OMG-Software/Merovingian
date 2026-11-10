// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/sync/StateGroupLookup.hpp"

#include "merovingian/events/Limits.hpp"
#include "merovingian/sync/GroupLookup.hpp"
#include "merovingian/sync/GroupLookupResult.hpp"

#include <unordered_set>

namespace merovingian::sync
{

auto lookup_state_in_group(database::PersistentStore const& store, std::string_view group_id,
                           std::string_view event_type, std::string_view state_key) -> GroupLookupResult
{
    auto visited = std::unordered_set<std::string_view>{};
    auto current = group_id;
    for (auto hops = std::size_t{0U};; ++hops)
    {
        if (!visited.insert(current).second || hops > events::max_state_group_delta_depth)
        {
            return {GroupLookup::broken, {}};
        }
        auto const group = store.state_groups.find(current);
        if (group == store.state_groups.end())
        {
            return {GroupLookup::broken, {}};
        }
        for (auto const& entry : store.state_group_state.entries_of(current))
        {
            if (entry.event_type == event_type && entry.state_key == state_key)
            {
                return {GroupLookup::found, entry.event_id};
            }
        }
        if (!group->parent_state_group_id.has_value())
        {
            return {GroupLookup::absent, {}};
        }
        current = *group->parent_state_group_id;
    }
}

} // namespace merovingian::sync
