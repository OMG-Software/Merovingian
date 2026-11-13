// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/RoomReloadSnapshot.hpp"
#include "merovingian/ipc/RoomSnapshotPage.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::ipc
{

// Joins the pages of one room snapshot on the federation worker (ADR-0733). Pages must arrive in order, all for the
// room and generation the assembler was made for, with the page count page 0 gave, and every row must belong to the
// room. Anything else spoils the assembly for good: the caller then fails the reload, it never applies part of a room.
class RoomSnapshotAssembler final
{
public:
    RoomSnapshotAssembler(std::string room_id, std::uint64_t generation);

    // Takes the next page. False, and the assembly is spoiled, when the page does not follow the rules above.
    [[nodiscard]] auto add_page(RoomSnapshotPage page) -> bool;
    // The page to ask for next: the number of pages taken so far.
    [[nodiscard]] auto next_page() const noexcept -> std::uint64_t;
    [[nodiscard]] auto complete() const noexcept -> bool;
    [[nodiscard]] auto spoiled() const noexcept -> bool;
    // The whole snapshot once complete, and only once; nullopt otherwise, and nullopt (spoiled) when a state-group
    // entry names no group of the snapshot or a group mapping names no event of it.
    [[nodiscard]] auto take() -> std::optional<database::RoomReloadSnapshot>;

private:
    [[nodiscard]] auto rows_belong_to_room(database::RoomReloadSnapshot const& rows) const -> bool;

    std::string room_id_{};
    std::uint64_t generation_{0U};
    std::uint64_t pages_{0U};
    std::uint64_t taken_{0U};
    bool spoiled_{false};
    bool handed_out_{false};
    database::RoomReloadSnapshot snapshot_{};
};

} // namespace merovingian::ipc
