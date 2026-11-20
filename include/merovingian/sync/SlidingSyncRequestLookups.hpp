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
#include <utility>
#include <vector>

namespace merovingian::sync
{
// The rows of one room `SlidingSyncRequestLookups::recency` reads, newest first, before it falls back to the room's
// newest event (ADR-0666).
inline constexpr std::size_t max_recency_rows_examined{1000U};

// What one sliding sync request needs to know about the caller's rooms, each learned once per request and then
// answered from memory (ADR-0665): the rooms the user is joined to and invited to (from the user's own membership
// rows), the rooms of their `m.direct`, and, per room, its type, whether it is a favourite, and its read markers (from
// the user's own receipt rows in the room, through the receipt index, ADR-0737). Without it every list, for every
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

    // The rooms the user has an invite membership in, less those `withhold_invite` named, in no particular order.
    [[nodiscard]] auto invited_rooms() -> std::vector<std::string>;

    // True when the user has an invite membership in `room_id` that `withhold_invite` did not name.
    [[nodiscard]] auto is_invited(std::string_view room_id) -> bool;

    // Leaves `room_id` out of `invited_rooms` and `is_invited` for the rest of the request: the caller may not show
    // this invite now (an ignored inviter, blocked invites, held room state that does not have it yet; ADR-0864).
    auto withhold_invite(std::string_view room_id) -> void;

    // MSC4186 "Lists": the server list also holds rooms the user "knocked on, left, or been kicked or banned from".
    // The rooms the user has a knock membership in, in no particular order.
    [[nodiscard]] auto knocked_rooms() -> std::vector<std::string>;

    // True when the user's membership in `room_id` is knock.
    [[nodiscard]] auto is_knocked(std::string_view room_id) -> bool;

    // Decides which rooms the user left, was kicked from or was banned from belong in the lists, and must run before
    // any list or `departed_rooms` reads them (ADR-0867): a room they were kicked or banned from always, unless banned
    // without ever joining; one they left themselves only if `previously_sent` holds it (this connection was sent it).
    // A room the user never joined whose kick a user they ignore sent is left out, as such an invite is.
    auto include_departed_rooms(std::unordered_set<std::string> const& previously_sent,
                                std::unordered_set<std::string> const& ignored_senders) -> void;

    // The rooms `include_departed_rooms` kept, in no particular order.
    [[nodiscard]] auto departed_rooms() -> std::vector<std::string>;

    // `leave` or `ban` for a room `include_departed_rooms` kept, or empty.
    [[nodiscard]] auto departed_membership(std::string_view room_id) -> std::string_view;

    // True when the user is not joined to `room_id`: invited, knocked, or departed. Such a room is ranked and filtered
    // by its membership only, never by events or state after it (ADR-0864, ADR-0867).
    [[nodiscard]] auto is_unjoined(std::string_view room_id) -> bool;

    // True when `room_id` is encrypted: its current m.room.encryption state event, or for an invited or knocked room
    // the stripped state it is sent, since a user only invited may not read the room's state (ADR-0864): the invite
    // record, or for a knock on a room this server holds, which keeps none, the room's current state. A departed room
    // counts as encrypted only when its encryption event predates the departure (ADR-0867).
    [[nodiscard]] auto is_encrypted(std::string_view room_id) -> bool;

    // True when `room_id` is in the user's m.direct.
    [[nodiscard]] auto is_dm(std::string_view room_id) -> bool;

    // True when `room_id` is tagged m.favourite for the user.
    [[nodiscard]] auto is_favourite(std::string_view room_id) -> bool;

    // The tags of the user's `m.tag` account data in `room_id` (MSC4186 `tags` / `not_tags`).
    [[nodiscard]] auto room_tags(std::string_view room_id) -> std::unordered_set<std::string> const&;

    // The rooms the current `m.space.child` state of `space_id` names with a non-empty `via`, or none when the user is
    // not joined to `space_id` (MSC4186 `spaces`: joined spaces only, no subspaces). Read once per space and request,
    // from the user's own join rows when the joined rooms have not been listed, never the room table.
    [[nodiscard]] auto space_children(std::string_view space_id) -> std::unordered_set<std::string> const&;

    // content.type of the room's m.room.create event (the stripped copy for an invited or knocked room, as for
    // `is_encrypted`), or empty.
    [[nodiscard]] auto room_type(std::string_view room_id) -> std::string const&;

    // Where the user has read up to in `room_id` (see read_markers_for), read once per room and request.
    [[nodiscard]] auto read_markers(std::string_view room_id) -> ReadMarkers const&;

    // The stream ordering of the room's newest event whose type is in `bump_types` (any event when empty), 0 when it
    // has none: the `by_recency` key. Read from the room's own rows, newest first, at most
    // `max_recency_rows_examined` of them per room; past that the room's newest event stands in (ADR-0666). Memoised
    // per room and set of bump types, so lists that share them share the work. For an invited room it is the
    // invite row's stream ordering, whatever the bump types: the user may not see the room's events (ADR-0864).
    [[nodiscard]] auto recency(std::string_view room_id, std::vector<std::string> const& bump_types) -> std::uint64_t;

    // content.name of the room's current m.room.name event (the stripped copy for an invited or knocked room, as for
    // `is_encrypted`), or empty: the `by_name` key.
    [[nodiscard]] auto room_name(std::string_view room_id) -> std::string const&;

    // Event rows `recency` has parsed or compared, in total: a test proves the cost by count.
    [[nodiscard]] auto recency_rows_visited() const noexcept -> std::uint64_t;

    // Rows of the user's memberships looked at: a test proves the pass happens once per request by count, not by time.
    [[nodiscard]] auto membership_rows_visited() const noexcept -> std::uint64_t;

    // Rows of the store's room table looked at: only `joined_rooms` reads it, so an invite or filter lookup costs the
    // user's own rows and never the server's rooms.
    [[nodiscard]] auto room_rows_visited() const noexcept -> std::uint64_t;

private:
    auto load_memberships() -> void;
    auto load_direct() -> void;

    database::PersistentStore const* m_store;
    std::string m_user;
    bool m_memberships_loaded{false};
    // The user's join rows, in row order, until `joined_rooms` keeps those whose room the store holds.
    std::vector<std::string> m_join_rows{};
    bool m_joined_resolved{false};
    std::vector<std::string> m_joined{};
    // Each invited room with its invite membership row's stream ordering.
    std::unordered_map<std::string, std::uint64_t> m_invited{};
    // Each knocked room with its knock row's stream ordering.
    std::unordered_map<std::string, std::uint64_t> m_knocked{};
    // Each `leave` or `ban` row, room to (stream ordering, membership), and those `include_departed_rooms` kept.
    std::unordered_map<std::string, std::pair<std::uint64_t, std::string>> m_departure_rows{};
    std::unordered_map<std::string, std::pair<std::uint64_t, std::string>> m_departed{};
    bool m_direct_loaded{false};
    std::unordered_set<std::string> m_direct{};
    std::unordered_map<std::string, std::unordered_set<std::string>> m_tags{};
    std::unordered_map<std::string, std::unordered_set<std::string>> m_space_children{};
    std::unordered_map<std::string, std::string> m_room_types{};
    std::unordered_map<std::string, ReadMarkers> m_markers{};
    std::uint64_t m_membership_rows_visited{0U};
    std::uint64_t m_room_rows_visited{0U};
    std::uint64_t m_recency_rows_visited{0U};
    std::unordered_map<std::string, std::unordered_map<std::string, std::uint64_t>> m_recency{};
    std::unordered_map<std::string, std::string> m_names{};
};

} // namespace merovingian::sync
