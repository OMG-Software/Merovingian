// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace merovingian::federation
{

struct BackfillRequest final
{
    std::string room_id{};
    std::vector<std::string> event_ids{};
    std::size_t limit{0U};
    // The X-Matrix-authenticated origin of the requesting server, filled in by
    // the inbound handler (never parsed from the request). The provider uses it
    // to refuse a server that has no joined user in the room (FED-2).
    std::string origin{};
};

} // namespace merovingian::federation
