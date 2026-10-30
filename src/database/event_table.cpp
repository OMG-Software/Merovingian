// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/event_table.hpp"

#include <algorithm>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <iterator>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

namespace merovingian::database
{
namespace
{

    [[nodiscard]] auto is_json_space(char c) noexcept -> bool
    {
        return c == ' ' || c == '\t' || c == '\n' || c == '\r';
    }

    // The integer value of the top-level member `key` of the JSON object `json`, or nullopt when the
    // member is absent, is not an integer that fits an int64, or `json` is not an object. One pass,
    // no allocation: strings are skipped (escapes honoured) and nesting is counted, so a member of
    // the same name inside `content` or `unsigned` is never taken for the event's own.
    [[nodiscard]] auto top_level_integer(std::string_view json, std::string_view key) -> std::optional<std::int64_t>
    {
        auto depth = 0U;
        auto index = std::size_t{0U};
        auto const size = json.size();
        while (index < size)
        {
            auto const c = json[index];
            if (c == '{' || c == '[')
            {
                ++depth;
                ++index;
                continue;
            }
            if (c == '}' || c == ']')
            {
                if (depth == 0U)
                {
                    return std::nullopt;
                }
                --depth;
                ++index;
                continue;
            }
            if (c != '"')
            {
                ++index;
                continue;
            }
            auto const start = ++index;
            while (index < size && json[index] != '"')
            {
                index += json[index] == '\\' ? 2U : 1U;
            }
            if (index >= size)
            {
                return std::nullopt;
            }
            auto const text = json.substr(start, index - start);
            ++index;
            if (depth != 1U || text != key)
            {
                continue;
            }
            auto after = index;
            while (after < size && is_json_space(json[after]))
            {
                ++after;
            }
            if (after >= size || json[after] != ':')
            {
                continue; // a string value that happens to equal `key`
            }
            ++after;
            while (after < size && is_json_space(json[after]))
            {
                ++after;
            }
            auto const begin = after;
            if (after < size && json[after] == '-')
            {
                ++after;
            }
            auto const digits = after;
            while (after < size && json[after] >= '0' && json[after] <= '9')
            {
                ++after;
            }
            if (after == digits || (after < size && (json[after] == '.' || json[after] == 'e' || json[after] == 'E')))
            {
                return std::nullopt;
            }
            auto value = std::int64_t{0};
            auto const parsed = std::from_chars(json.data() + begin, json.data() + after, value);
            if (parsed.ec != std::errc{} || parsed.ptr != json.data() + after)
            {
                return std::nullopt;
            }
            return value;
        }
        return std::nullopt;
    }

} // namespace

auto EventTable::time_entry_for(PersistentEvent const& row, std::size_t position) -> std::optional<TimeEntry>
{
    if (row.status == "outlier" || row.status == "rejected" || row.status == "soft_failed")
    {
        return std::nullopt;
    }
    auto const ts = top_level_integer(row.json, "origin_server_ts");
    if (!ts.has_value())
    {
        return std::nullopt;
    }
    return TimeEntry{*ts, row.depth, row.stream_ordering, position};
}

auto EventTable::index_time(std::size_t position) -> void
{
    auto const entry = time_entry_for(rows_[position], position);
    if (!entry.has_value())
    {
        return;
    }
    auto& entries = by_room_time_.try_emplace(rows_[position].room_id).first->second;
    // The common case: a new event is the newest of its room.
    if (entries.empty() || entries.back() <= *entry)
    {
        entries.push_back(*entry);
        return;
    }
    entries.insert(std::ranges::upper_bound(entries, *entry), *entry);
}

auto EventTable::unindex_time(std::string_view room_id, std::optional<TimeEntry> const& entry) -> void
{
    if (!entry.has_value())
    {
        return;
    }
    auto const room = by_room_time_.find(room_id);
    if (room == by_room_time_.end())
    {
        return;
    }
    auto& entries = room->second;
    auto const at = std::ranges::lower_bound(entries, *entry);
    if (at != entries.end() && *at == *entry)
    {
        entries.erase(at);
    }
    if (entries.empty())
    {
        by_room_time_.erase(room);
    }
}

auto EventTable::find(std::string_view event_id) const -> const_iterator
{
    auto const entry = by_id_.find(event_id);
    if (entry == by_id_.end())
    {
        return rows_.end();
    }
    return rows_.begin() + static_cast<std::ptrdiff_t>(entry->second);
}

auto EventTable::contains(std::string_view event_id) const -> bool
{
    return by_id_.contains(event_id);
}

auto EventTable::with_id(std::string_view event_id) const -> std::ranges::subrange<const_iterator>
{
    auto const first = find(event_id);
    return {first, first == rows_.end() ? first : std::next(first)};
}

auto EventTable::find_in_room(std::string_view room_id, std::string_view event_id) const -> const_iterator
{
    auto const event = find(event_id);
    return event != rows_.end() && event->room_id == room_id ? event : rows_.end();
}

auto EventTable::insert(PersistentEvent event) -> bool
{
    if (by_id_.contains(event.event_id))
    {
        return false;
    }
    auto const position = rows_.size();
    auto const stream_ordering = event.stream_ordering;
    by_id_.emplace(event.event_id, position);
    rows_.push_back(std::move(event));
    index_time(position);

    // The common case: the newest event so far goes on the end of the stream order.
    if (stream_order_.empty() || rows_[stream_order_.back()].stream_ordering <= stream_ordering)
    {
        stream_order_.push_back(position);
        return true;
    }
    // An event that committed after a newer one: after every row with a stream_ordering no greater
    // than its own, so equal stream orderings stay in the order they were added.
    auto const after = std::ranges::upper_bound(stream_order_, stream_ordering, {}, [this](std::size_t held) {
        return rows_[held].stream_ordering;
    });
    stream_order_.insert(after, position);
    return true;
}

auto EventTable::insert_all(std::vector<PersistentEvent> events) -> std::size_t
{
    auto const first_added = rows_.size();
    rows_.reserve(rows_.size() + events.size());
    by_id_.reserve(by_id_.size() + events.size());
    for (auto& event : events)
    {
        if (by_id_.contains(event.event_id))
        {
            continue;
        }
        by_id_.emplace(event.event_id, rows_.size());
        rows_.push_back(std::move(event));
    }

    // Positions of the added rows go on the end in ascending order; a stable sort of that tail and a
    // stable merge with the existing order keep equal stream orderings in the order they were added.
    auto const held = static_cast<std::ptrdiff_t>(stream_order_.size());
    stream_order_.reserve(rows_.size());
    for (auto position = first_added; position < rows_.size(); ++position)
    {
        stream_order_.push_back(position);
    }
    auto const stream_ordering_of = [this](std::size_t position) {
        return rows_[position].stream_ordering;
    };
    std::ranges::stable_sort(stream_order_.begin() + held, stream_order_.end(), {}, stream_ordering_of);
    std::ranges::inplace_merge(stream_order_, stream_order_.begin() + held, {}, stream_ordering_of);

    // The room-and-time index the same way: append each added row's entry to its room, then sort
    // each touched room's new tail once and merge it, instead of one shift per row.
    auto touched = std::unordered_map<std::string, std::size_t>{};
    for (auto position = first_added; position < rows_.size(); ++position)
    {
        auto const entry = time_entry_for(rows_[position], position);
        if (!entry.has_value())
        {
            continue;
        }
        auto& entries = by_room_time_[rows_[position].room_id];
        touched.try_emplace(rows_[position].room_id, entries.size());
        entries.push_back(*entry);
    }
    for (auto const& [room_id, old_size] : touched)
    {
        auto& entries = by_room_time_[room_id];
        auto const middle = entries.begin() + static_cast<std::ptrdiff_t>(old_size);
        std::ranges::sort(middle, entries.end());
        std::ranges::inplace_merge(entries, middle);
    }
    return rows_.size() - first_added;
}

auto EventTable::erase_marked(std::vector<bool> const& removed) -> std::size_t
{
    // Old position -> position after removal; `gone` for a removed row.
    constexpr auto gone = std::numeric_limits<std::size_t>::max();
    auto remap = std::vector<std::size_t>(rows_.size(), gone);
    auto kept = std::size_t{0U};
    for (auto position = std::size_t{0U}; position < rows_.size(); ++position)
    {
        if (removed[position])
        {
            continue;
        }
        if (kept != position)
        {
            rows_[kept] = std::move(rows_[position]);
        }
        remap[position] = kept;
        ++kept;
    }
    auto const removed_count = rows_.size() - kept;
    rows_.resize(kept);

    std::erase_if(by_id_, [&remap](auto const& entry) {
        return remap[entry.second] == gone;
    });
    for (auto& entry : by_id_)
    {
        entry.second = remap[entry.second];
    }

    // Removing rows does not change the relative order of the rest, so the surviving positions are
    // already in stream order once renumbered.
    std::erase_if(stream_order_, [&remap](std::size_t position) {
        return remap[position] == gone;
    });
    for (auto& position : stream_order_)
    {
        position = remap[position];
    }

    // The same for the room-and-time index. Renumbering keeps each room's entries in key order: the
    // position is the key's last field, only a tie-break, and removal keeps rows' relative order.
    for (auto room = by_room_time_.begin(); room != by_room_time_.end();)
    {
        std::erase_if(room->second, [&remap](TimeEntry const& entry) {
            return remap[entry.position] == gone;
        });
        for (auto& entry : room->second)
        {
            entry.position = remap[entry.position];
        }
        room = room->second.empty() ? by_room_time_.erase(room) : std::next(room);
    }
    return removed_count;
}

auto EventTable::extract() -> std::vector<PersistentEvent>
{
    auto rows = std::move(rows_);
    clear();
    return rows;
}

auto EventTable::clear() noexcept -> void
{
    rows_.clear();
    by_id_.clear();
    stream_order_.clear();
    by_room_time_.clear();
}

auto EventTable::reserve(size_type capacity) -> void
{
    rows_.reserve(capacity);
    by_id_.reserve(capacity);
    stream_order_.reserve(capacity);
}

} // namespace merovingian::database
