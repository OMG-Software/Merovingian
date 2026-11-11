// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/TimelineWindow.hpp"

#include <algorithm>

namespace merovingian::sync
{

auto newest_timeline_window(database::PersistentStore const& store, std::string_view room_id,
                            std::optional<std::uint64_t> after, std::uint64_t up_to, std::size_t cap,
                            std::function<bool(database::PersistentEvent const&)> const& wanted) -> TimelineWindow
{
    auto window = TimelineWindow{};
    auto const rows = store.events.room_in_stream_order(room_id);
    auto const last = std::ranges::upper_bound(rows, up_to, {}, &database::PersistentEvent::stream_ordering);
    auto const first = after.has_value()
                           ? std::ranges::upper_bound(rows, *after, {}, &database::PersistentEvent::stream_ordering)
                           : rows.begin();
    auto skipped = std::size_t{0U};
    for (auto row = last; row > first;)
    {
        --row;
        auto const& event = *row;
        store.sync_timeline_rows_examined.add(1U);
        window.oldest_examined = event.stream_ordering;
        // ADR-0064 phase B2: a rejected or soft-failed event is never relayed to clients (spec "Rejection", "Soft
        // failure"). The response's `state` section is built separately, so a soft-failed state event that resolution
        // later admits into current state is still delivered there.
        if (event.status != "rejected" && event.status != "soft_failed" && wanted(event))
        {
            window.matched.push_back(&event);
            if (window.matched.size() > cap)
            {
                break;
            }
            continue;
        }
        ++skipped;
        if (skipped == max_timeline_rows_skipped && row != first)
        {
            window.budget_ran_out = true;
            break;
        }
    }
    std::ranges::reverse(window.matched);
    return window;
}

} // namespace merovingian::sync
