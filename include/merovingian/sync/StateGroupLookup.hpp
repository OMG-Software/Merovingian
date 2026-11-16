// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/sync/GroupLookupResult.hpp"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::sync
{

// The event ID that `group_id`'s full state holds for (event_type, state_key), walking the delta chain newest
// first exactly as database::read_state_group_full_state does: bounded, cycle-checked, and `broken` (not
// `absent`) when a group on the chain is missing. It scans each group on the chain once, so it costs the
// chain's rows, not the room's events.
[[nodiscard]] auto lookup_state_in_group(database::PersistentStore const& store, std::string_view group_id,
                                         std::string_view event_type, std::string_view state_key) -> GroupLookupResult;

// The event IDs of the state `group_id` holds that differs from what its ancestor `ancestor_id` holds: the newest row
// of each key on the delta chain from `group_id` down to, not including, `ancestor_id`. Empty when the two are one
// group. Nullopt when `ancestor_id` is not on the chain (a snapshot, a missing group or a cycle comes first), and the
// caller compares the two states. It costs the rows of the groups between the two, not the room's state: a snapshot's
// rows are never read. A key that changed and changed back is reported, with the value it holds.
[[nodiscard]] auto state_changes_along_chain(database::PersistentStore const& store, std::string_view ancestor_id,
                                             std::string_view group_id) -> std::optional<std::vector<std::string>>;

} // namespace merovingian::sync
