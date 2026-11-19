// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::sync
{

// An unexpired sticky event of a room that this server holds as an accepted event.
struct StickyCandidate final
{
    std::string event_id{};
    std::string sender{};
    // The event's stream ordering.
    std::uint64_t ordering{0U};
};

} // namespace merovingian::sync
