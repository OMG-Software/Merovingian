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
    // MSC4186 `is_invited`, or MSC3575's `is_invite`.
    std::optional<bool> is_invite{};
    std::optional<bool> is_dm{};
    std::optional<bool> is_favourite{};
    // m.room.create content.type allow- and denylists. A JSON `null` entry, MSC4186's "rooms which do not have a room
    // type", is held as the empty string, which is what a room without a type reads as.
    std::vector<std::string> room_types{};
    std::vector<std::string> not_room_types{};
    // MSC4186 `spaces`: rooms an `m.space.child` state event of one of these joined spaces names (no subspaces).
    std::vector<std::string> spaces{};
    // MSC4186 `tags` and `not_tags` (which wins): the room's `m.tag` account data.
    std::vector<std::string> tags{};
    std::vector<std::string> not_tags{};

    [[nodiscard]] auto operator==(SlidingSyncFilters const&) const -> bool = default;
};

} // namespace merovingian::sync
