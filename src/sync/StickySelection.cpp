// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/StickySelection.hpp"

#include "merovingian/trust_safety/IgnoreList.hpp"

#include <algorithm>
#include <string>

namespace merovingian::sync
{

auto sticky_candidates_of_room(database::PersistentStore const& store, std::string_view room_id, std::int64_t now_ms)
    -> std::vector<StickyCandidate>
{
    auto candidates = std::vector<StickyCandidate>{};
    for (auto const* const row : store.sticky_events.unexpired_of_room(room_id, now_ms))
    {
        auto const found = store.events.find_in_room(room_id, row->event_id);
        if (found == store.events.end() || found->status != "accepted")
        {
            continue;
        }
        // The sticky exemption skips history visibility only: a redaction that has not been applied stays withheld
        // (rooms/v3.md "Handling redactions"; ADR-0862), as HistoryVisibility::can_see withholds it.
        if (database::redaction_is_withheld(store, found->event_id))
        {
            continue;
        }
        candidates.push_back({found->event_id, found->sender_user_id, found->stream_ordering});
    }
    return candidates;
}

auto select_sticky_for_sync(std::vector<StickyCandidate> const& candidates, std::uint64_t upper_bound,
                            std::optional<std::uint64_t> after, std::unordered_set<std::string> const& ignored_senders,
                            std::unordered_set<std::string> const& excluded, std::size_t limit) -> StickyChoice
{
    auto eligible = std::vector<StickyCandidate const*>{};
    for (auto const& candidate : candidates)
    {
        if (candidate.ordering > upper_bound || (after.has_value() && candidate.ordering <= *after) ||
            excluded.contains(candidate.event_id) ||
            trust_safety::is_delivery_suppressed(ignored_senders, candidate.sender, /*is_state_event=*/false))
        {
            continue;
        }
        eligible.push_back(&candidate);
    }
    std::ranges::sort(eligible, [](StickyCandidate const* a, StickyCandidate const* b) {
        return a->ordering != b->ordering ? a->ordering < b->ordering : a->event_id < b->event_id;
    });
    auto choice = StickyChoice{};
    choice.more = eligible.size() > limit;
    for (auto it = eligible.begin(); it != eligible.end() && choice.event_ids.size() < limit; ++it)
    {
        choice.event_ids.push_back((*it)->event_id);
    }
    return choice;
}

} // namespace merovingian::sync
