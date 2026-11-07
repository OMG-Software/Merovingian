// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStore.hpp"

#include <cstddef>

namespace merovingian::homeserver
{

// What one user directory search did, so a test can hold it to a bound that does not grow with the number of
// profiles that match.
struct UserDirectorySearchStats final
{
    // Whole passes over the account table (`store.users`): 1 however many profiles match.
    std::size_t user_table_walks{0U};
    // Profiles whose display name or user ID was searched.
    std::size_t profiles_examined{0U};
};

} // namespace merovingian::homeserver
