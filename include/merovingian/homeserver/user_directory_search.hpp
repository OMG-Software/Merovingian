// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/folded_substring.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <cstddef>
#include <vector>

namespace merovingian::homeserver
{

// The most results POST /user_directory/search returns whatever `limit` asks for (ADR-0334). The spec
// defaults `limit` to 10 and sets no maximum; the response's `limited` says the list was cut.
inline constexpr std::size_t max_user_directory_results = 100U;

// What one user directory search did, so a test can hold it to a bound that does not grow with the number of
// profiles that match.
struct UserDirectorySearchStats final
{
    // Whole passes over the account table (`store.users`): 1 however many profiles match.
    std::size_t user_table_walks{0U};
    // Profiles whose display name or user ID was searched.
    std::size_t profiles_examined{0U};
};

// The profiles whose display name or user ID holds the matcher's term, in the store's order, leaving out
// those of a deactivated account (0.12.13 audit item 5: it can never log in again, so it is not offered as
// someone to contact). The accounts are read in one pass into a set of the deactivated ones; the old code
// rescanned every account for each matching profile (security audit run 2, F-50; ADR-0334). Visibility to
// the requester is judged by the caller. Call with `runtime.mutex` held.
[[nodiscard]] auto matching_directory_profiles(database::PersistentStore const& store,
                                               core::FoldedSubstringMatcher& matcher, UserDirectorySearchStats& stats)
    -> std::vector<database::PersistentProfile const*>;

} // namespace merovingian::homeserver
