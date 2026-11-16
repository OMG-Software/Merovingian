// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <cstddef>
#include <string>
#include <string_view>
#include <unordered_map>

namespace merovingian::homeserver
{

// ADR-0761: servers that gave no answer to a client's remote profile lookup (no address, no connection, no TLS
// session or no response before the deadline), remembered for `ttl` so that the lookups which follow fail at once
// instead of each holding a client outbound slot for the whole deadline. A server that answers at all, even with an
// error, is forgotten. Holds at most `capacity` servers. Not thread-safe: the runtime guards it with runtime.mutex.
class RecentlyUnreachableServers final
{
public:
    using Clock = std::chrono::steady_clock;

    static constexpr auto default_ttl = std::chrono::seconds{60};
    static constexpr auto default_capacity = std::size_t{4096U};

    RecentlyUnreachableServers() = default;
    // `capacity` 0 remembers nothing.
    RecentlyUnreachableServers(Clock::duration ttl, std::size_t capacity) noexcept;

    // Whether `server` gave no answer less than `ttl` before `now`.
    [[nodiscard]] auto contains(std::string_view server, Clock::time_point now) const -> bool;
    // Records that `server` gave no answer at `now`. When the set is full, expired entries are dropped first and then
    // the server remembered longest, so a burst of distinct servers cannot grow it past `capacity`.
    auto remember(std::string_view server, Clock::time_point now) -> void;
    // Forgets `server`, which has answered.
    auto forget(std::string_view server) -> void;
    [[nodiscard]] auto size() const noexcept -> std::size_t;

private:
    auto make_room(Clock::time_point now) -> void;

    Clock::duration m_ttl{default_ttl};
    std::size_t m_capacity{default_capacity};
    std::unordered_map<std::string, Clock::time_point> m_failed_at{};
};

} // namespace merovingian::homeserver
