// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>

namespace merovingian::homeserver
{

// When the appservice drainer may next try an appservice that has just failed, and the delay it
// will apply if that attempt fails too (doubling from 1 s up to a 5 minute cap).
struct AppserviceDeliveryBackoff final
{
    std::chrono::steady_clock::time_point retry_at{};
    std::chrono::milliseconds delay{0};
};

} // namespace merovingian::homeserver
