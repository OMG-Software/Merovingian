// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/user_directory_search.hpp"

#include "merovingian/core/folded_substring.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <string_view>
#include <unordered_set>
#include <vector>

namespace merovingian::homeserver
{

auto matching_directory_profiles(database::PersistentStore const& store, core::FoldedSubstringMatcher& matcher,
                                 UserDirectorySearchStats& stats) -> std::vector<database::PersistentProfile const*>
{
    auto deactivated = std::unordered_set<std::string_view>{};
    ++stats.user_table_walks;
    for (auto const& account : store.users)
    {
        if (account.deactivated)
        {
            deactivated.insert(account.user_id);
        }
    }

    auto matched = std::vector<database::PersistentProfile const*>{};
    for (auto const& profile : store.profiles)
    {
        ++stats.profiles_examined;
        if (!matcher.contains(profile.displayname) && !matcher.contains(profile.user_id))
        {
            continue;
        }
        if (deactivated.contains(profile.user_id))
        {
            continue;
        }
        matched.push_back(&profile);
    }
    return matched;
}

} // namespace merovingian::homeserver
