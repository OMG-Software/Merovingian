// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <optional>
#include <string>
#include <vector>

namespace merovingian::federation
{

struct PublicRoomsFilter final
{
    std::string generic_search_term{};
    // Not specified: every room, whatever its type. Specified: only rooms of a listed type, with an entry
    // holding no value standing for the spec's `null`, "rooms without a room type". An empty list searches
    // for no type, so it lists nothing.
    std::optional<std::vector<std::optional<std::string>>> room_types{};
};

} // namespace merovingian::federation
