// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/ExaminedRows.hpp"

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace merovingian::database
{

// Every change to a room's resolved current state since the process started, keyed by the sync position from which a
// client sees it (ADR-0827). `/sync`'s `state_after` reads it to tell a client exactly what changed between two
// positions, whatever the shape of the event graph: the state at a position is the current state with each key changed
// above that position put back to the value its first such change replaced.
//
// The key of a change is the stream ordering of the event whose storing made it, raised above every position a sync
// has already answered (`note_served`), so a change is never filed at or below a position a client was told about
// before it happened. A key is therefore final once the position is served, and the state as of a served position never
// changes.
//
// In memory only, and inactive until `start`: the federation worker, which serves no sync, records nothing. It is
// bounded per room and in all; dropping a room's oldest change raises that room's horizon, and a position below the
// horizon is no longer covered, so the caller sends the whole state there (an update the client already holds is
// harmless). Not thread-safe: every call is made with `runtime.mutex` held, as every writer of current state and every
// sync holds it.
class StateChangeLog final
{
public:
    // One change of one key. An empty `previous_event_id` is a key that had no value; an empty `event_id` a key
    // removed.
    struct Change final
    {
        std::string event_type{};
        std::string state_key{};
        std::string previous_event_id{};
        std::string event_id{};
        std::uint64_t position{0U};
    };

    // At most this many changes are held for one room, and in all. Past either the oldest go first.
    static constexpr auto max_changes_per_room = std::size_t{1024U};
    static constexpr auto max_changes = std::size_t{65536U};

    // Starts recording. Every position at or below `floor` predates the log, so it is covered for no room, and the
    // first change is filed above it. Clears anything recorded before.
    auto start(std::uint64_t floor) -> void;
    [[nodiscard]] auto active() const noexcept -> bool;

    // Records that a sync answered as of `position`: a change recorded afterwards is filed above it.
    auto note_served(std::uint64_t position) noexcept -> void;

    // Records that `room_id`'s value for (`event_type`, `state_key`) went from `previous_event_id` to `event_id`, made
    // by storing the event at stream ordering `causing_position` (0 when no event caused it). Nothing when inactive or
    // when the value did not change.
    auto record(std::string_view room_id, std::string_view event_type, std::string_view state_key,
                std::string_view previous_event_id, std::string_view event_id, std::uint64_t causing_position) -> void;

    // Forgets `room_id`'s changes, for a writer that replaced its current state wholesale (a room reload): no position
    // served so far is covered for it any more, and the state as of any later one is rebuilt from the new rows.
    auto forget_room(std::string_view room_id) -> void;

    // Whether every change of `room_id` above `position` is held, so the state as of `position` can be rebuilt, and
    // `position` is above the floor, so a state a client was told as of it was told by this process from this log.
    [[nodiscard]] auto covers(std::string_view room_id, std::uint64_t position) const -> bool;

    // Whether `room_id` has a change above `position`. One lookup.
    [[nodiscard]] auto has_change_after(std::string_view room_id, std::uint64_t position) const -> bool;

    // The changes of `room_id` above `position`, by position and, at one position, in the order they were made. Each
    // one returned is counted in `rows_examined`. The pointers stay valid until the next call that records or starts.
    [[nodiscard]] auto changes_after(std::string_view room_id, std::uint64_t position) const
        -> std::vector<Change const*>;

    // The number of changes held, for every room.
    [[nodiscard]] auto size() const noexcept -> std::size_t;

    // The changes `changes_after` returned, so a test proves a reader's cost by count, not by time.
    [[nodiscard]] auto rows_examined() const noexcept -> ExaminedRows const&;

private:
    // A room's changes keyed by (position, sequence), and the position at or below which its changes are no longer all
    // held.
    struct RoomChanges final
    {
        std::map<std::pair<std::uint64_t, std::uint64_t>, Change> changes{};
        std::uint64_t horizon{0U};
    };

    // The lowest position no sync has been answered at.
    [[nodiscard]] auto above_served() const noexcept -> std::uint64_t;
    auto drop_oldest_of_room(RoomChanges& room) -> void;
    auto drop_oldest() -> void;

    bool m_active{false};
    std::uint64_t m_floor{0U};
    std::uint64_t m_served{0U};
    std::uint64_t m_next_sequence{0U};
    std::unordered_map<std::string, RoomChanges> m_rooms{};
    // Every held change by sequence, oldest first: its room and position, so the oldest can be dropped in O(log n).
    std::map<std::uint64_t, std::pair<std::string, std::uint64_t>> m_order{};
    ExaminedRows m_rows_examined{};
};

} // namespace merovingian::database
