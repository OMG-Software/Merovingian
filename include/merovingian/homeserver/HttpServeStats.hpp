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
        : accepted_connections{other.accepted_connections.load(std::memory_order_relaxed)}
        , completed_requests{other.completed_requests.load(std::memory_order_relaxed)}
        , rejected_requests{other.rejected_requests.load(std::memory_order_relaxed)}
    {
        other.accepted_connections.store(0U, std::memory_order_relaxed);
        other.completed_requests.store(0U, std::memory_order_relaxed);
        other.rejected_requests.store(0U, std::memory_order_relaxed);
    }
    auto operator=(HttpServeStats&& other) noexcept -> HttpServeStats&
    {
        if (this != &other)
        {
            accepted_connections.store(other.accepted_connections.load(std::memory_order_relaxed),
                                       std::memory_order_relaxed);
            completed_requests.store(other.completed_requests.load(std::memory_order_relaxed),
                                     std::memory_order_relaxed);
            rejected_requests.store(other.rejected_requests.load(std::memory_order_relaxed), std::memory_order_relaxed);
            other.accepted_connections.store(0U, std::memory_order_relaxed);
            other.completed_requests.store(0U, std::memory_order_relaxed);
            other.rejected_requests.store(0U, std::memory_order_relaxed);
        }
        return *this;
    }
    HttpServeStats(HttpServeStats const&) = delete;
    auto operator=(HttpServeStats const&) = delete;
};

} // namespace merovingian::homeserver
