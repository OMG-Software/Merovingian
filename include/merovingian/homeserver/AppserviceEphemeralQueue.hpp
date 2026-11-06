// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/AppserviceEphemeralItem.hpp"

#include <cstdint>
#include <deque>

namespace merovingian::homeserver
{

// Its implicit move can throw under libstdc++ (std::deque member); see ADR-0268 before changing that.
struct AppserviceEphemeralQueue final
{
    std::deque<AppserviceEphemeralItem> items{};
    // Items discarded because the queue was full, since the process started (a metric).
    std::uint64_t dropped{0U};
};

} // namespace merovingian::homeserver
