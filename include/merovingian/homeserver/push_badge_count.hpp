// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/push/push_rules.hpp"

#include <cstdint>
#include <string_view>

namespace merovingian::homeserver
{

struct HomeserverRuntime;

// The Push Gateway API's `counts.unread` ("the number of unread messages a user has across all of
// the rooms they are a member of") for one recipient (ADR-0207). Push delivery computes it under
// runtime.mutex for every recipient of every notifying event, so its work must not grow with the
// store: one pass over at most push_badge_row_budget store rows, every row charged before any
// filter, thread-parent lookups included. The count saturates at push_badge_unread_cap: it is a
// badge, and clients do not show counts that large in full.
inline constexpr auto push_badge_unread_cap = std::uint32_t{1000U};
inline constexpr auto push_badge_row_budget = std::uint64_t{10000U};

struct PushBadgeCount final
{
    // The badge, at most push_badge_unread_cap.
    std::uint32_t unread{0U};
    // Store rows the pass visited, thread-parent lookups included.
    std::uint64_t rows_visited{0U};
    // The pass ran out of rows before visiting every row of the store. `unread` is then a lower
    // bound: it counts only events the visited rows prove unread.
    bool capped{false};
};

// The badge for `user_id` by `ruleset` (the rules delivery already loaded for them), over at most
// `row_budget` rows. One pass, newest row first, across all of the user's joined rooms: it records
// the read receipts' targets, the user's own events (which read their thread), the user's
// membership changes and the candidate events, then applies them independently of row order with
// the same rules as sync::count_unread_by_thread over read_receipt_markers and current_join_start.
// When the pass visits every row the badge equals the sum of those exact per-room counts.
//
// When it is capped it never counts more than the exact count would, except as noted in ADR-0207:
// a room is skipped when the pass did not reach its join or the target of one of its receipts, and
// a candidate whose thread could not be determined is skipped.
//
// Call with runtime.mutex held.
[[nodiscard]] auto count_push_badge(HomeserverRuntime const& runtime, std::string_view user_id,
                                    push::PushRuleset const& ruleset, std::uint64_t row_budget = push_badge_row_budget)
    -> PushBadgeCount;

// count_push_badge(...).unread with the default budget.
[[nodiscard]] auto push_badge_unread_count(HomeserverRuntime const& runtime, std::string_view user_id,
                                           push::PushRuleset const& ruleset) -> std::uint32_t;

} // namespace merovingian::homeserver
