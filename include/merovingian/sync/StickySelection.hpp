// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/sync/StickyCandidate.hpp"
#include "merovingian/sync/StickyChoice.hpp"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace merovingian::sync
{

// The room's unexpired sticky events (ADR-0854) that are accepted events of that room held in the event table, found
// through the sticky table's room index and the event table's ID index: the cost is the room's sticky rows. A row whose
// event is missing, in another room, or rejected, soft-failed or an outlier is left out. The caller holds the lock the
// store needs.
[[nodiscard]] auto sticky_candidates_of_room(database::PersistentStore const& store, std::string_view room_id,
                                             std::int64_t now_ms) -> std::vector<StickyCandidate>;

// Which of `candidates` a sync response carries for one room (ADR-0855). Pure. A candidate is chosen when its ordering is
// at most `upper_bound` and above `after` (when given), its sender is not in `ignored_senders`, and its event ID is not
// in `excluded` (what the timeline carries, and for sliding sync what the connection was already sent). The result is
// oldest first (ordering, then event ID) and holds at most `limit` events; `more` says whether eligible ones were left.
[[nodiscard]] auto select_sticky_for_sync(std::vector<StickyCandidate> const& candidates, std::uint64_t upper_bound,
                                          std::optional<std::uint64_t> after,
                                          std::unordered_set<std::string> const& ignored_senders,
                                          std::unordered_set<std::string> const& excluded, std::size_t limit)
    -> StickyChoice;

} // namespace merovingian::sync
