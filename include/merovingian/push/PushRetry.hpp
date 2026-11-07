// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/push/PushGatewayNotification.hpp"

#include <chrono>
#include <cstdint>
#include <string>

namespace merovingian::push
{

// One notification to one pusher that failed and may be tried again.
struct PushRetry final
{
    std::string user_id{};
    std::string app_id{};
    std::string pushkey{};
    std::string gateway_url{};
    PushGatewayNotification notification{};
    // Attempts that have failed: 0 before the first attempt. schedule() is given the count that
    // includes the attempt that has just failed.
    std::uint32_t failed_attempts{0U};
    std::chrono::steady_clock::time_point due{};
};

} // namespace merovingian::push
