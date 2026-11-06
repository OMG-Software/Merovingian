// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstdint>
#include <string>

namespace merovingian::homeserver
{

struct InboundTypingUser final
{
    std::string room_id{};
    std::string user_id{};
    bool typing{false};
    std::uint64_t stream_id{0U};
    // When this typing stops on its own. The default never expires; every path that sets
    // `typing` to true sets it.
    std::chrono::steady_clock::time_point expires_at{std::chrono::steady_clock::time_point::max()};
};

} // namespace merovingian::homeserver
