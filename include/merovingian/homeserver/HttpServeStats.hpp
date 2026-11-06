// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <atomic>
#include <cstdint>

namespace merovingian::homeserver
{

struct HttpServeStats final
{
    std::atomic<std::uint64_t> accepted_connections{0U};
    std::atomic<std::uint64_t> completed_requests{0U};
    std::atomic<std::uint64_t> rejected_requests{0U};

    HttpServeStats() = default;
    HttpServeStats(HttpServeStats&& other) noexcept
        : accepted_connections{other.accepted_connections.load()}
        , completed_requests{other.completed_requests.load()}
        , rejected_requests{other.rejected_requests.load()}
    {
        other.accepted_connections.store(0U);
        other.completed_requests.store(0U);
        other.rejected_requests.store(0U);
    }
    auto operator=(HttpServeStats&& other) noexcept -> HttpServeStats&
    {
        if (this != &other)
        {
            accepted_connections.store(other.accepted_connections.load());
            completed_requests.store(other.completed_requests.load());
            rejected_requests.store(other.rejected_requests.load());
            other.accepted_connections.store(0U);
            other.completed_requests.store(0U);
            other.rejected_requests.store(0U);
        }
        return *this;
    }
    HttpServeStats(HttpServeStats const&) = delete;
    auto operator=(HttpServeStats const&) = delete;
};

} // namespace merovingian::homeserver
