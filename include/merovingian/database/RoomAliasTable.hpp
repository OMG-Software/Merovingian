// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentRoomAlias.hpp"
#include "merovingian/database/StateGroupKeyHash.hpp"

#include <cstddef>
#include <functional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace merovingian::database
{

// `room_aliases`: one row per alias, found by alias, listed by room and counted by creator without a scan
// (security audit run-4 F-03, ADR-0581). The class owns the rows and shows them read-only, so a writer that bypasses
// it does not compile and the three indexes cannot drift from the rows (ADR-0325). Indexes hold positions into
// `rows_`, so the defaulted copy and move keep them valid (ADR-0523). Row order is not relied on: an erase moves the
// last row into the hole.
class RoomAliasTable final
{
public:
    using value_type = PersistentRoomAlias;
    using size_type = std::size_t;
    using const_iterator = std::vector<PersistentRoomAlias>::const_iterator;
    using iterator = const_iterator;

    [[nodiscard]] auto begin() const noexcept -> const_iterator
    {
        return rows_.begin();
    }
    [[nodiscard]] auto end() const noexcept -> const_iterator
    {
        return rows_.end();
    }
    [[nodiscard]] auto size() const noexcept -> size_type
    {
        return rows_.size();
    }
    [[nodiscard]] auto empty() const noexcept -> bool
    {
        return rows_.empty();
    }
    [[nodiscard]] auto operator[](size_type position) const -> PersistentRoomAlias const&
    {
        return rows_[position];
    }

    // The row for `alias`, or nullptr. A hash lookup; valid until the table is next changed.
    [[nodiscard]] auto find(std::string_view alias) const -> PersistentRoomAlias const*;
    [[nodiscard]] auto contains(std::string_view alias) const -> bool;
    // The aliases that name `room_id`, in no particular order. Costs the room's own aliases, not the table.
    [[nodiscard]] auto aliases_of_room(std::string_view room_id) const -> std::vector<std::string>;
    [[nodiscard]] auto count_for_room(std::string_view room_id) const -> size_type;
    // How many aliases `creator_user_id` created. An empty creator (a legacy row) is not counted.
    [[nodiscard]] auto count_for_creator(std::string_view creator_user_id) const -> size_type;

    // Adds `alias`. False, and nothing changes, when its alias is already held.
    auto insert(PersistentRoomAlias alias) -> bool;
    // Removes `alias`. False when it is not held.
    auto erase(std::string_view alias) -> bool;
    // Points `alias` at `room_id`, keeping its creator. False when `alias` is not held.
    auto reassign(std::string_view alias, std::string_view room_id) -> bool;
    auto clear() noexcept -> void;

private:
    using PositionsByKey =
        std::unordered_map<std::string, std::vector<std::size_t>, detail::StateGroupKeyHash, std::equal_to<>>;

    auto unindex_room(std::string_view room_id, std::size_t position) -> void;
    auto index_room(std::string_view room_id, std::size_t position) -> void;
    auto count_creator(std::string_view creator_user_id, bool added) -> void;

    std::vector<PersistentRoomAlias> rows_{};
    // alias -> position in rows_.
    std::unordered_map<std::string, std::size_t, detail::StateGroupKeyHash, std::equal_to<>> by_alias_{};
    // room_id -> positions in rows_ of the aliases naming it.
    PositionsByKey by_room_{};
    // creator_user_id -> how many rows it created.
    std::unordered_map<std::string, std::size_t, detail::StateGroupKeyHash, std::equal_to<>> by_creator_{};
};

} // namespace merovingian::database
