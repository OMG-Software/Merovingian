// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::homeserver
{

// How a GET /presence/{userId}/status is answered.
enum class PresenceReadStatus : std::uint8_t
{
    ok,
    forbidden,
    not_found,
};

} // namespace merovingian::homeserver
