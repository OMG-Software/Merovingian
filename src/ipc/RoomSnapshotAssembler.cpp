// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/ipc/RoomSnapshotAssembler.hpp"

#include <algorithm>
#include <iterator>
#include <string_view>
#include <unordered_set>
#include <utility>

namespace merovingian::ipc
{

RoomSnapshotAssembler::RoomSnapshotAssembler(std::string room_id, std::uint64_t generation)
    : room_id_{std::move(room_id)}
    , generation_{generation}
{
    snapshot_.room_id = room_id_;
}

auto RoomSnapshotAssembler::add_page(RoomSnapshotPage page) -> bool
{
    auto const in_order = page.page == taken_ && (taken_ == 0U ? page.pages > 0U : page.pages == pages_);
    auto const same_room = page.room_id == room_id_ && page.generation == generation_;
    // Only page 0 may carry the room row, and its room must be this room.
    auto const room_row_ok = page.rows.room.has_value() ? page.page == 0U && page.rows.room->room_id == room_id_ : true;
    if (spoiled_ || handed_out_ || complete() || !in_order || !same_room || !room_row_ok ||
        !rows_belong_to_room(page.rows))
    {
        spoiled_ = true;
        return false;
    }
    pages_ = page.pages;
    ++taken_;
    auto& rows = page.rows;
    if (rows.room.has_value())
    {
        snapshot_.room = std::move(rows.room);
    }
    std::ranges::move(rows.memberships, std::back_inserter(snapshot_.memberships));
    std::ranges::move(rows.invites, std::back_inserter(snapshot_.invites));
    std::ranges::move(rows.events, std::back_inserter(snapshot_.events));
    std::ranges::move(rows.state, std::back_inserter(snapshot_.state));
    std::ranges::move(rows.state_groups, std::back_inserter(snapshot_.state_groups));
    std::ranges::move(rows.state_group_state, std::back_inserter(snapshot_.state_group_state));
    std::ranges::move(rows.event_state_groups, std::back_inserter(snapshot_.event_state_groups));
    std::ranges::move(rows.forward_extremities, std::back_inserter(snapshot_.forward_extremities));
    return true;
}

auto RoomSnapshotAssembler::next_page() const noexcept -> std::uint64_t
{
    return taken_;
}

auto RoomSnapshotAssembler::complete() const noexcept -> bool
{
    return !spoiled_ && pages_ > 0U && taken_ == pages_;
}

auto RoomSnapshotAssembler::spoiled() const noexcept -> bool
{
    return spoiled_;
}

auto RoomSnapshotAssembler::take() -> std::optional<database::RoomReloadSnapshot>
{
    if (!complete() || handed_out_)
    {
        return std::nullopt;
    }
    handed_out_ = true;
    // The rows with no room of their own must hang off this room's groups and events, which may sit on other pages.
    auto group_ids = std::unordered_set<std::string_view>{};
    for (auto const& group : snapshot_.state_groups)
    {
        group_ids.insert(group.state_group_id);
    }
    auto event_ids = std::unordered_set<std::string_view>{};
    for (auto const& event : snapshot_.events)
    {
        event_ids.insert(event.event_id);
    }
    auto const entries_ok = std::ranges::all_of(snapshot_.state_group_state, [&group_ids](auto const& entry) {
        return group_ids.contains(entry.state_group_id);
    });
    auto const mappings_ok = std::ranges::all_of(snapshot_.event_state_groups, [&event_ids](auto const& mapping) {
        return event_ids.contains(mapping.event_id);
    });
    if (!entries_ok || !mappings_ok)
    {
        spoiled_ = true;
        return std::nullopt;
    }
    return std::move(snapshot_);
}

auto RoomSnapshotAssembler::rows_belong_to_room(database::RoomReloadSnapshot const& rows) const -> bool
{
    // A state-group entry and an event's group mapping carry no room: they are tied to it through a group or an
    // event of this room, which apply_room_snapshot replaces by ID.
    auto const of_room = [this](auto const& row) {
        return row.room_id == room_id_;
    };
    return std::ranges::all_of(rows.memberships, of_room) && std::ranges::all_of(rows.invites, of_room) &&
           std::ranges::all_of(rows.events, of_room) && std::ranges::all_of(rows.state, of_room) &&
           std::ranges::all_of(rows.state_groups, of_room) && std::ranges::all_of(rows.forward_extremities, of_room);
}

} // namespace merovingian::ipc
