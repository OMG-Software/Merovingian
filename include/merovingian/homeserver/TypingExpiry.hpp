// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/InboundTypingUser.hpp"

#include <chrono>
#include <optional>
#include <vector>

namespace merovingian::homeserver
{

// What expire_typing changed.
struct TypingExpiry final
{
    // Some room's typing users changed, so its typing stream position advanced.
    bool changed{false};
    // This server's own users whose typing expired: remote servers in their rooms are told
    // they stopped.
    std::vector<InboundTypingUser> expired_local{};
    // The earliest expiry still pending, if any.
    std::optional<std::chrono::steady_clock::time_point> next_expiry{};
};

} // namespace merovingian::homeserver
