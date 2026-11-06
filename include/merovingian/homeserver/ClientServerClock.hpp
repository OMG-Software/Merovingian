// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>

namespace merovingian::homeserver
{

// Wall-clock source for the rate-limit engine. The engine takes a
// callable; we hold the state inline so the engine (a unique_ptr) can
// borrow it. Default-constructed runtimes start at steady_clock origin.
struct ClientServerClock final
{
    [[nodiscard]] auto operator()() const noexcept -> std::chrono::steady_clock::time_point
    {
        return std::chrono::steady_clock::now();
    }
};

} // namespace merovingian::homeserver
