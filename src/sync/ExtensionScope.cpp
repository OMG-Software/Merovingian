// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/ExtensionScope.hpp"

#include <algorithm>
#include <string_view>
#include <unordered_set>

namespace merovingian::sync
{

namespace
{

    // Whether a scope key names every list or subscription: absent, or holding "*".
    [[nodiscard]] auto names_every(std::optional<std::vector<std::string>> const& key) -> bool
    {
        return !key.has_value() || std::ranges::find(*key, std::string_view{"*"}) != key->end();
    }

} // namespace

auto extension_scope_rooms(std::optional<std::vector<std::string>> const& lists,
                           std::optional<std::vector<std::string>> const& rooms,
                           std::map<std::string, std::vector<std::string>> const& list_windows,
                           std::vector<std::string> const& subscriptions) -> std::vector<std::string>
{
    auto scope = std::vector<std::string>{};
    auto seen = std::unordered_set<std::string>{};
    auto const add = [&](std::string const& room_id) {
        if (seen.insert(room_id).second)
        {
            scope.push_back(room_id);
        }
    };
    if (names_every(lists))
    {
        for (auto const& [key, window] : list_windows)
        {
            std::ranges::for_each(window, add);
        }
    }
    else
    {
        for (auto const& key : *lists)
        {
            if (auto const found = list_windows.find(key); found != list_windows.end())
            {
                std::ranges::for_each(found->second, add);
            }
        }
    }
    if (names_every(rooms))
    {
        std::ranges::for_each(subscriptions, add);
    }
    else
    {
        auto const named = std::unordered_set<std::string>{rooms->begin(), rooms->end()};
        for (auto const& room_id : subscriptions)
        {
            if (named.contains(room_id))
            {
                add(room_id);
            }
        }
    }
    return scope;
}

} // namespace merovingian::sync
