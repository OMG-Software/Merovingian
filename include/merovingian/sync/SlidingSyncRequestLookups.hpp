// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/sync/ReadMarkers.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace merovingian::sync
{
// The rows of one room `SlidingSyncRequestLookups::recency` reads, newest first, before it falls back to the room's
// newest event (ADR-0666).
inline constexpr std::size_t max_recency_rows_examined{1000U};

// What one sliding sync request needs to know about the caller's rooms, each learned once per request and then
// answered from memory (ADR-0665): the rooms the user is joined to and invited to (from the user's own membership
// rows), the rooms of their `m.direct`, and, per room, its type, whether it is a favourite, and its read markers (from
// the user's own receipt rows in the room, through the receipt index, ADR-0651). Without it every list, for every
// joined room, scanned the whole membership, state or receipt table, so a list cost the rooms times the table.
//
// A request owns one, on its thread and under runtime.mutex; it is not thread-safe and its caches fill through
// non-const functions (ADR-0525). It reads `store` only, which must outlive it and not change while it is used.
class SlidingSyncRequestLookups final
{
public:
    SlidingSyncRequestLookups(database::PersistentStore const& store, std::string_view user);

    // The rooms the user is joined to that the store holds a room record for, in no particular order.
    [[nodiscard]] auto joined_rooms() -> std::vector<std::string> const&;

    // True when the user has an invite membership in `room_id`.
    [[nodiscard]] auto is_invited(std::string_view room_id) -> bool;

    // True when `room_id` has a current m.room.encryption state event.
    [[nodiscard]] auto is_encrypted(std::string_view room_id) const -> bool;

    // True when `room_id` is in the user's m.direct.
    [[nodiscard]] auto is_dm(std::string_view room_id) -> bool;

    // True when `room_id` is tagged m.favourite for the user.
    [[nodiscard]] auto is_favourite(std::string_view room_id) -> bool;

    // content.type of the room's m.room.create event, or empty.
    [[nodiscard]] auto room_type(std::string_view room_id) -> std::string const&;

    // Where the user has read up to in `room_id` (see read_markers_for), read once per room and request.
    [[nodiscard]] auto read_markers(std::string_view room_id) -> ReadMarkers const&;

    // The stream ordering of the room's newest event whose type is in `bump_types` (any event when empty), 0 when it
    // has none: the `by_recency` key. Read from the room's own rows, newest first, at most
    // `max_recency_rows_examined` of them per room; past that the room's newest event stands in (ADR-0666). Memoised
    // per room and set of bump types, so lists that share them share the work.
    [[nodiscard]] auto recency(std::string_view room_id, std::vector<std::string> const& bump_types) -> std::uint64_t;

    // content.name of the room's current m.room.name event, or empty: the `by_name` key.
    [[nodiscard]] auto room_name(std::string_view room_id) -> std::string const&;

    // Event rows `recency` has parsed or compared, in total: a test proves the cost by count.
    [[nodiscard]] auto recency_rows_visited() const noexcept -> std::uint64_t;

    // Rows of the user's memberships looked at: a test proves the pass happens once per request by count, not by time.
    [[nodiscard]] auto membership_rows_visited() const noexcept -> std::uint64_t;

private:
    auto load_memberships() -> void;
    auto load_direct() -> void;

    database::PersistentStore const* m_store;
    std::string m_user;
    bool m_memberships_loaded{false};
    std::vector<std::string> m_joined{};
    std::unordered_set<std::string> m_invited{};
    bool m_direct_loaded{false};
    std::unordered_set<std::string> m_direct{};
    std::unordered_map<std::string, bool> m_favourites{};
    std::unordered_map<std::string, std::string> m_room_types{};
    std::unordered_map<std::string, ReadMarkers> m_markers{};
    std::uint64_t m_membership_rows_visited{0U};
    std::uint64_t m_recency_rows_visited{0U};
    std::unordered_map<std::string, std::unordered_map<std::string, std::uint64_t>> m_recency{};
    std::unordered_map<std::string, std::string> m_names{};
};

} // namespace merovingian::sync
