// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/event_table.hpp"

#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/events/limits.hpp"

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
#include <unordered_set>
#include <utility>
#include <variant>
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

    [[nodiscard]] auto string_member_of(canonicaljson::Object const& object, std::string_view key) -> std::string const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return std::get_if<std::string>(&member.value->storage());
            }
        }
        return nullptr;
    }

    [[nodiscard]] auto object_member_of(canonicaljson::Object const& object, std::string_view key)
        -> canonicaljson::Object const*
    {
        for (auto const& member : object)
        {
            if (member.key == key)
            {
                return std::get_if<canonicaljson::Object>(&member.value->storage());
            }
        }
        return nullptr;
    }

    // The kind the server aggregates for `rel_type`, or nullopt for any other (not indexed).
    [[nodiscard]] auto relation_kind_of(std::string_view rel_type) noexcept -> std::optional<RelationKind>
    {
        if (rel_type == "m.replace")
        {
            return RelationKind::replace;
        }
        if (rel_type == "m.thread")
        {
            return RelationKind::thread;
        }
        if (rel_type == "m.reference")
        {
            return RelationKind::reference;
        }
        return std::nullopt;
    }

} // namespace

auto EventTable::relation_key_for(PersistentEvent const& row) -> std::optional<RelationKey>
{
    // Stored events are canonical JSON, so the member is spelt this way when present. A row without
    // it costs one substring search, not a parse (the prefilter sync::event_thread_id uses too).
    if (row.json.find("\"m.relates_to\"") == std::string::npos)
    {
        return std::nullopt;
    }
    auto const parsed = canonicaljson::parse_lossless(row.json);
    if (parsed.error != canonicaljson::ParseError::none)
    {
        return std::nullopt;
    }
    auto const* event = std::get_if<canonicaljson::Object>(&parsed.value.storage());
    auto const* content = event == nullptr ? nullptr : object_member_of(*event, "content");
    auto const* relates = content == nullptr ? nullptr : object_member_of(*content, "m.relates_to");
    if (relates == nullptr)
    {
        return std::nullopt;
    }
    auto const* target = string_member_of(*relates, "event_id");
    auto const* rel_type = string_member_of(*relates, "rel_type");
    // The target is client-chosen text used as a key: an empty or over-long one names no event.
    if (target == nullptr || rel_type == nullptr || target->empty() || target->size() > events::max_id_length_bytes)
    {
        return std::nullopt;
    }
    auto const kind = relation_kind_of(*rel_type);
    if (!kind.has_value())
    {
        return std::nullopt;
    }
    return RelationKey{*target, *kind};
}

auto EventTable::index_relation(std::size_t position, RelationKey const& key) -> void
{
    relation_children_[key.target][static_cast<std::size_t>(key.kind)].push_back(position);
}

auto EventTable::unindex_relation(std::size_t position, RelationKey const& key) -> void
{
    auto const target = relation_children_.find(key.target);
    if (target == relation_children_.end())
    {
        return;
    }
    std::erase(target->second[static_cast<std::size_t>(key.kind)], position);
    if (std::ranges::all_of(target->second, [](std::vector<std::size_t> const& list) {
            return list.empty();
        }))
    {
        relation_children_.erase(target);
    }
}

auto EventTable::relation_child_count(std::string_view target_event_id) const -> std::size_t
{
    auto const target = relation_children_.find(target_event_id);
    if (target == relation_children_.end())
    {
        return std::size_t{0U};
    }
    auto total = std::size_t{0U};
    for (auto const& list : target->second)
    {
        total += list.size();
    }
    return total;
}

auto EventTable::relation_child_count(std::string_view target_event_id, RelationKind kind) const -> std::size_t
{
    auto const target = relation_children_.find(target_event_id);
    return target == relation_children_.end() ? std::size_t{0U} : target->second[static_cast<std::size_t>(kind)].size();
}

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

auto EventTable::index_stream(std::size_t position) -> void
{
    auto const stream_ordering = rows_[position].stream_ordering;
    auto& positions = by_room_stream_.try_emplace(rows_[position].room_id).first->second;
    // The common case: a new event is the newest of its room.
    if (positions.empty() || rows_[positions.back()].stream_ordering <= stream_ordering)
    {
        positions.push_back(position);
        return;
    }
    // After every row with a stream_ordering no greater than its own, as in the global stream order.
    auto const after = std::ranges::upper_bound(positions, stream_ordering, {}, [this](std::size_t held) {
        return rows_[held].stream_ordering;
    });
    positions.insert(after, position);
}

auto EventTable::unindex_stream(std::string_view room_id, std::size_t position, std::uint64_t stream_ordering) -> void
{
    auto const room = by_room_stream_.find(room_id);
    if (room == by_room_stream_.end())
    {
        return;
    }
    auto& positions = room->second;
    auto const same_ordering = std::ranges::equal_range(positions, stream_ordering, {}, [this](std::size_t held) {
        return rows_[held].stream_ordering;
    });
    auto const at = std::ranges::find(same_ordering, position);
    if (at != same_ordering.end())
    {
        positions.erase(at);
    }
    if (positions.empty())
    {
        by_room_stream_.erase(room);
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

auto EventTable::latest_ts_of(PersistentEvent const& row) -> std::int64_t
{
    auto const ts = top_level_integer(row.json, "origin_server_ts");
    return ts.has_value() && *ts > 0 ? *ts : std::int64_t{0};
}

auto EventTable::recompute_latest_ts(std::string_view room_id) -> void
{
    auto latest = std::int64_t{0};
    if (auto const room = by_room_stream_.find(room_id); room != by_room_stream_.end())
    {
        for (auto const position : room->second)
        {
            latest = std::max(latest, latest_ts_of(rows_[position]));
        }
    }
    if (latest > 0)
    {
        room_latest_ts_.insert_or_assign(std::string{room_id}, latest);
    }
    else if (auto const held = room_latest_ts_.find(room_id); held != room_latest_ts_.end())
    {
        room_latest_ts_.erase(held);
    }
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
    index_stream(position);
    if (auto const latest = latest_ts_of(rows_[position]); latest > 0)
    {
        auto& held = room_latest_ts_.try_emplace(rows_[position].room_id, latest).first->second;
        held = std::max(held, latest);
    }
    if (auto const relation = relation_key_for(rows_[position]); relation.has_value())
    {
        index_relation(position, *relation);
    }

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
        if (auto const latest = latest_ts_of(event); latest > 0)
        {
            auto& held = room_latest_ts_.try_emplace(event.room_id, latest).first->second;
            held = std::max(held, latest);
        }
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

    // The room-and-stream index the same way: append each added row to its room, then sort each
    // touched room's new tail (stable, so equal stream orderings keep the order they were added) and
    // merge it with the rows the room already held.
    auto touched_streams = std::unordered_map<std::string, std::size_t>{};
    for (auto position = first_added; position < rows_.size(); ++position)
    {
        auto& positions = by_room_stream_[rows_[position].room_id];
        touched_streams.try_emplace(rows_[position].room_id, positions.size());
        positions.push_back(position);
    }
    for (auto const& [room_id, old_size] : touched_streams)
    {
        auto& positions = by_room_stream_[room_id];
        auto const middle = positions.begin() + static_cast<std::ptrdiff_t>(old_size);
        std::ranges::stable_sort(middle, positions.end(), {}, stream_ordering_of);
        std::ranges::inplace_merge(positions, middle, {}, stream_ordering_of);
    }

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
    for (auto position = first_added; position < rows_.size(); ++position)
    {
        if (auto const relation = relation_key_for(rows_[position]); relation.has_value())
        {
            index_relation(position, *relation);
        }
    }
    return rows_.size() - first_added;
}

auto EventTable::erase_marked(std::vector<bool> const& removed) -> std::size_t
{
    // Old position -> position after removal; `gone` for a removed row.
    constexpr auto gone = std::numeric_limits<std::size_t>::max();
    auto remap = std::vector<std::size_t>(rows_.size(), gone);
    auto rooms_losing_rows = std::unordered_set<std::string>{};
    for (auto position = std::size_t{0U}; position < rows_.size(); ++position)
    {
        if (removed[position])
        {
            rooms_losing_rows.insert(rows_[position].room_id);
        }
    }
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

    // The same for the room-and-stream index.
    for (auto room = by_room_stream_.begin(); room != by_room_stream_.end();)
    {
        std::erase_if(room->second, [&remap](std::size_t position) {
            return remap[position] == gone;
        });
        for (auto& position : room->second)
        {
            position = remap[position];
        }
        room = room->second.empty() ? by_room_stream_.erase(room) : std::next(room);
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

    // And the relation index: renumber the survivors, drop a removed child and an emptied target.
    for (auto target = relation_children_.begin(); target != relation_children_.end();)
    {
        auto empty = true;
        for (auto& list : target->second)
        {
            std::erase_if(list, [&remap](std::size_t position) {
                return remap[position] == gone;
            });
            for (auto& position : list)
            {
                position = remap[position];
            }
            empty = empty && list.empty();
        }
        target = empty ? relation_children_.erase(target) : std::next(target);
    }
    for (auto const& room_id : rooms_losing_rows)
    {
        recompute_latest_ts(room_id);
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
    by_room_stream_.clear();
    by_room_time_.clear();
    relation_children_.clear();
    room_latest_ts_.clear();
}

auto EventTable::reserve(size_type capacity) -> void
{
    rows_.reserve(capacity);
    by_id_.reserve(capacity);
    stream_order_.reserve(capacity);
}

} // namespace merovingian::database

namespace merovingian::database
{

auto EventTable::room_latest_origin_server_ts(std::string_view room_id) const -> std::int64_t
{
    auto const held = room_latest_ts_.find(room_id);
    return held == room_latest_ts_.end() ? std::int64_t{0} : held->second;
}

} // namespace merovingian::database
