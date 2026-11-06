// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/AppserviceEphemeralItem.hpp"

#include <cstdint>
#include <list>
#include <type_traits>

namespace merovingian::homeserver
{

struct AppserviceEphemeralQueue final
{
    std::list<AppserviceEphemeralItem> items{};
    // Items discarded because the queue was full, since the process started (a metric).
    std::uint64_t dropped{0U};
};

static_assert(std::is_nothrow_move_constructible_v<AppserviceEphemeralQueue> &&
              std::is_nothrow_move_assignable_v<AppserviceEphemeralQueue>);

} // namespace merovingian::homeserver
