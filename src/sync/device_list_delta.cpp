// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/sync/device_list_delta.hpp"

#include <algorithm>
#include <map>
#include <utility>

namespace merovingian::sync
{

auto collect_device_list_delta(database::PersistentStore const& store, std::string_view user,
                               std::uint64_t from_sync_stream_id, std::uint64_t to_sync_stream_id) -> DeviceListDelta
{
    auto delta = DeviceListDelta{};
    delta.max_stream_id = from_sync_stream_id;

    // Collapse the store's append-only change log to one entry per subject.
    // Without this a subject appears once per row, so a long-lived observer's
    // initial response repeats the same handful of user IDs thousands of times.
    auto latest_by_subject = std::map<std::string, std::pair<std::uint64_t, bool>>{};
    for (auto const& change : store.device_list_changes)
    {
        if (change.observer_user_id != user || change.stream_id <= from_sync_stream_id ||
            change.stream_id > to_sync_stream_id)
        {
            continue;
        }
        if (change.stream_id > delta.max_stream_id)
        {
            delta.max_stream_id = change.stream_id;
        }
        auto const is_left = change.change_type == "left";
        auto const existing = latest_by_subject.find(change.subject_user_id);
        if (existing == latest_by_subject.end())
        {
            latest_by_subject.emplace(change.subject_user_id, std::pair{change.stream_id, is_left});
            continue;
        }
        // The store is not guaranteed to be ordered by stream id, so compare
        // rather than assume the last row read is the most recent one.
        if (change.stream_id >= existing->second.first)
        {
            existing->second = {change.stream_id, is_left};
        }
    }

    // std::map iterates in key order, so both lists come out sorted by user ID.
    for (auto const& [subject, latest] : latest_by_subject)
    {
        if (latest.second)
        {
            delta.left.push_back(subject);
        }
        else
        {
            delta.changed.push_back(subject);
        }
    }
    return delta;
}

} // namespace merovingian::sync
