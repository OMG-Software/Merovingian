// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>

namespace merovingian::homeserver
{

struct SpaceHierarchyResult final
{
    std::uint16_t status{200U};
    std::string body{};
    // Set with status 429: the delay to advertise as `retry_after_ms`.
    std::uint32_t retry_after_ms{0U};
    // The rooms the walk looked at to answer (ADR-0345): bounded by the page asked for and by
    // `max_hierarchy_walk_visits`, never by the size of the space.
    std::size_t rooms_visited{0U};
};

} // namespace merovingian::homeserver
