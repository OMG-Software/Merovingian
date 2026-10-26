// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/cached_server_discovery.hpp"

#include "merovingian/federation/security.hpp"

#include <algorithm>
#include <mutex>
#include <string>
#include <string_view>
#include <utility>

namespace merovingian::federation
{

CachedServerDiscovery::CachedServerDiscovery(ServerDiscoveryNetwork& upstream, std::uint64_t ttl_ms,
                                             std::function<std::uint64_t()> now_ms, std::size_t capacity)
    : upstream_{upstream}
    , ttl_ms_{ttl_ms}
    , now_ms_{std::move(now_ms)}
    , capacity_{capacity}
{
}

auto CachedServerDiscovery::discover(std::string_view server_name, std::uint32_t timeout_seconds)
    -> ServerDiscoveryResult
{
    if (!server_name_is_valid(server_name))
    {
        auto result = ServerDiscoveryResult{};
        result.reason = "invalid server name";
        return result;
    }
    auto const key = std::string{server_name};
    auto const now = now_ms_ ? now_ms_() : std::uint64_t{0U};

    // Fast path: serve a fresh entry under the lock. The upstream network call
    // below is never made while holding `mutex_`, so a slow discovery for one
    // server does not block concurrent lookups for another.
    {
        auto const lock = std::lock_guard<std::mutex>{mutex_};
        std::erase_if(cache_, [now, this](auto const& item) {
            return now < item.second.fetched_at_ms || now - item.second.fetched_at_ms >= ttl_ms_;
        });
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
    auto const completed_at = now_ms_ ? now_ms_() : std::uint64_t{0U};
    std::erase_if(cache_, [completed_at, this](auto const& item) {
        return completed_at < item.second.fetched_at_ms || completed_at - item.second.fetched_at_ms >= ttl_ms_;
    });
    if (capacity_ != 0U && ttl_ms_ != 0U && completed_at >= now && completed_at - now < ttl_ms_)
    {
        if (!cache_.contains(key) && cache_.size() >= capacity_)
        {
            auto const oldest = std::ranges::min_element(cache_, [](auto const& left, auto const& right) {
                return left.second.fetched_at_ms < right.second.fetched_at_ms ||
                       (left.second.fetched_at_ms == right.second.fetched_at_ms && left.first < right.first);
            });
            cache_.erase(oldest);
        }
        cache_.insert_or_assign(key, Entry{result, now});
    }
    return result;
}

auto CachedServerDiscovery::size() const -> std::size_t
{
    auto const lock = std::lock_guard<std::mutex>{mutex_};
    return cache_.size();
}

auto CachedServerDiscovery::lookup_addresses_filtered(std::string_view host, std::uint16_t port) -> ResolvedAddressSet
{
    auto const resolved = upstream_.lookup_addresses(host, port);
    if (!resolved.ok)
    {
        return resolved;
    }
    // Pusher gateway and identity-server URLs come through here, so the
    // federation-only allow_private_ip_ranges is deliberately not applied
    // (ADR-0230).
    if (!address_set_allowed(resolved.addresses, upstream_.denied_ip_ranges()))
    {
        return ResolvedAddressSet{false, {}, "resolved address set contains disallowed addresses"};
    }
    return resolved;
}

auto CachedServerDiscovery::upstream() noexcept -> ServerDiscoveryNetwork&
{
    return upstream_;
}

} // namespace merovingian::federation