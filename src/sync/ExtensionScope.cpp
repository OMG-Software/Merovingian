// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/ExtensionScope.hpp"

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace merovingian::sync
{

namespace
{

    // The entries a scope key names, or nullptr when it names every list or subscription: absent, or holding "*".
    [[nodiscard]] auto named_entries(std::optional<std::vector<std::string>> const& key)
        -> std::vector<std::string> const*
    {
        if (!key.has_value())
        {
            return nullptr;
        }
        auto const& entries = key.value();
        return std::ranges::find(entries, std::string_view{"*"}) != entries.end() ? nullptr : &entries;
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
    if (auto const* named_lists = named_entries(lists); named_lists == nullptr)
    {
        for (auto const& [key, window] : list_windows)
        {
            std::ranges::for_each(window, add);
        }
    }
    else
    {
        for (auto const& key : *named_lists)
        {
            if (auto const found = list_windows.find(key); found != list_windows.end())
            {
                std::ranges::for_each(found->second, add);
            }
        }
    }
    if (auto const* named_rooms = named_entries(rooms); named_rooms == nullptr)
    {
        std::ranges::for_each(subscriptions, add);
    }
    else
    {
        auto const named = std::unordered_set<std::string>{named_rooms->begin(), named_rooms->end()};
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

auto joined_extension_scope_rooms(std::optional<std::vector<std::string>> const& lists,
                                  std::optional<std::vector<std::string>> const& rooms,
                                  ExtensionScopeSource const& source,
                                  std::map<std::string, RoomAccess, std::less<>> const& room_access)
    -> std::vector<std::string>
{
    auto scope = extension_scope_rooms(lists, rooms, source.list_windows, source.subscriptions);
    std::erase_if(scope, [&room_access](std::string const& room_id) {
        auto const found = room_access.find(room_id);
        return found == room_access.end() || found->second != RoomAccess::joined;
    });
    return scope;
}

} // namespace merovingian::sync
