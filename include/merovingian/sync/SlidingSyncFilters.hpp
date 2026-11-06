// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <optional>
#include <string>
#include <vector>

namespace merovingian::sync
{

// MSC4186 §lists[*].filters — predicates for narrowing the room list.
struct SlidingSyncFilters final
{
    std::optional<bool> is_encrypted{};
    std::optional<bool> is_invite{};
    std::optional<bool> is_dm{};
    std::optional<bool> is_favourite{};
    std::vector<std::string> room_types{};     // m.room.create content.type allowlist
    std::vector<std::string> not_room_types{}; // m.room.create content.type denylist

    [[nodiscard]] auto operator==(SlidingSyncFilters const&) const -> bool = default;
};

} // namespace merovingian::sync
