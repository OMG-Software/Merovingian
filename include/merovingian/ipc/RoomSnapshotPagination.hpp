// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::ipc
{

// A room snapshot cut into frame bodies (ADR-0733): `pages` in order, or none and a `refusal` naming why the room
// cannot be sent (a single row over the page budget is refused, never truncated).
struct RoomSnapshotPagination final
{
    std::vector<std::string> pages{};
    std::string refusal{};
};

} // namespace merovingian::ipc
