// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/OAuthClock.hpp"

#include "merovingian/homeserver/HomeserverRuntime.hpp"

#include <chrono>
#include <cstdint>

namespace merovingian::homeserver
{

auto oauth_wall_clock_ms() -> std::uint64_t
{
    auto const now =
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch());
    return now.count() < 0 ? std::uint64_t{0U} : static_cast<std::uint64_t>(now.count());
}

auto oauth_device_clock_ms(HomeserverRuntime const& runtime) -> std::uint64_t
{
    return oauth_wall_clock_ms() + runtime.test_device_grant_clock_advance_ms;
}

} // namespace merovingian::homeserver
