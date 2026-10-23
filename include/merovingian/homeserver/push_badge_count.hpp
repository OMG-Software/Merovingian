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
// store: one walk of the events, newest first in stream order (ADR-0215), that stops once every
// joined room is settled and visits at most push_badge_row_budget rows. The count saturates at
// push_badge_unread_cap: it is a badge, and clients do not show counts that large in full.
inline constexpr auto push_badge_unread_cap = std::uint32_t{1000U};
inline constexpr auto push_badge_row_budget = std::uint64_t{10000U};

struct PushBadgeCount final
{
    // The badge, at most push_badge_unread_cap.
    std::uint32_t unread{0U};
    // Event rows the walk visited. Thread-parent lookups are hash lookups and are not counted.
    std::uint64_t rows_visited{0U};
    // Whole store tables walked outside the event walk to set it up: the memberships, the read
    // receipts, and the classifier's (PushRuleUnreadClassifier::table_walks). Each once per badge,
    // however many rooms the user is in.
    std::uint64_t table_walks{0U};
    // The walk ran out of rows before every room was settled. `unread` is then a lower bound: an
    // unsettled room counts only events above the lowest row visited.
    bool capped{false};
};

// The badge for `user_id` by `ruleset` (the rules delivery already loaded for them), over at most
// `row_budget` rows. Before the walk it reads the joined rooms and each read receipt's position.
// The walk meets every row newest first, so by the time it reaches a candidate event it has met
// every own event (which reads its thread) and every membership change above it. A room is
// settled, and its rows below are skipped, once nothing below can change its count: the walk has
// passed below a non-join membership change, which pins the start of the current join, or has met
// a join at or below the unthreaded read marker with only joins above. The walk stops when every
// joined room is settled. Its rules are sync::count_unread_by_thread's over read_markers_for and
// current_join_start, so an uncapped badge equals the sum of those exact per-room counts.
//
// Capped, it never counts more than the exact count: an unsettled room counts only candidates
// above the lowest row visited, from the earliest join met there, or, when it met no membership
// change, from its membership row's ordering (at or after the join start), and nothing when that
// is 0.
//
// Call with runtime.mutex held.
[[nodiscard]] auto count_push_badge(HomeserverRuntime const& runtime, std::string_view user_id,
                                    push::PushRuleset const& ruleset, std::uint64_t row_budget = push_badge_row_budget)
    -> PushBadgeCount;

// count_push_badge(...).unread with the default budget.
[[nodiscard]] auto push_badge_unread_count(HomeserverRuntime const& runtime, std::string_view user_id,
                                           push::PushRuleset const& ruleset) -> std::uint32_t;

} // namespace merovingian::homeserver
