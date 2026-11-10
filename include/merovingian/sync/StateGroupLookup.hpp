// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/sync/GroupLookupResult.hpp"

#include <string_view>

namespace merovingian::sync
{

// The event ID that `group_id`'s full state holds for (event_type, state_key), walking the delta chain newest
// first exactly as database::read_state_group_full_state does: bounded, cycle-checked, and `broken` (not
// `absent`) when a group on the chain is missing. It scans each group on the chain once, so it costs the
// chain's rows, not the room's events.
[[nodiscard]] auto lookup_state_in_group(database::PersistentStore const& store, std::string_view group_id,
                                         std::string_view event_type, std::string_view state_key) -> GroupLookupResult;

} // namespace merovingian::sync
