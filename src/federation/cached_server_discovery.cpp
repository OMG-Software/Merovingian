// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/cached_server_discovery.hpp"

#include <mutex>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::federation
{

CachedServerDiscovery::CachedServerDiscovery(ServerDiscoveryNetwork& upstream, std::uint64_t ttl_ms,
                                             std::function<std::uint64_t()> now_ms)
    : upstream_{upstream}
    , ttl_ms_{ttl_ms}
    , now_ms_{std::move(now_ms)}
{
}

auto CachedServerDiscovery::discover(std::string_view server_name, std::uint32_t timeout_seconds)
    -> ServerDiscoveryResult
{
    auto const key = std::string{server_name};
    auto const now = now_ms_ ? now_ms_() : std::uint64_t{0U};

    // Fast path: serve a fresh entry under the lock. The upstream network call
    // below is never made while holding `mutex_`, so a slow discovery for one
    // server does not block concurrent lookups for another.
    {
        auto const lock = std::lock_guard<std::mutex>{mutex_};
        auto const it = cache_.find(key);
        if (it != cache_.end() && (now - it->second.fetched_at_ms) < ttl_ms_)
        {
            return it->second.result;
        }
    }

    auto result = discover_server(server_name, upstream_, timeout_seconds);

    // Cache both positive and negative results for the TTL so a failing
    // server does not trigger a full DNS cascade on every PDU in a large
    // inbound transaction. `pinned_addresses` are refreshed on the next miss.
    auto const lock = std::lock_guard<std::mutex>{mutex_};
    cache_[key] = Entry{result, now};
    return result;
}

auto CachedServerDiscovery::upstream() noexcept -> ServerDiscoveryNetwork&
{
    return upstream_;
}

} // namespace merovingian::federation