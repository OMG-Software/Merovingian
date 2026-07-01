// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/federation/server_discovery.hpp"

#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <unordered_map>

namespace merovingian::federation
{

// Wraps a `ServerDiscoveryNetwork` with an in-memory, TTL-bounded cache of
// `ServerDiscoveryResult` keyed by server name. `discover_server` is a free
// function (not a virtual), so this wrapper is a plain owning class rather
// than a `ServerDiscoveryNetwork` subclass.
//
// The cache exists because the remote-key resolver and the outbound
// membership paths used to re-run the full `.well-known` + SRV + DNS cascade
// on every call, even cache hits. A 60s TTL bounds staleness so SSRF
// `pinned_addresses` never go stale past TTL: if DNS changes, the next call
// re-runs discovery and returns fresh pins. Negative results
// (`discovery_allowed == false`) are cached for the same TTL so a failing
// server does not hammer DNS on every PDU in a large inbound transaction.
//
// Thread-safe: all map reads and writes are guarded by `mutex_`. The upstream
// network call is never made while holding the mutex, so a slow lookup does
// not block concurrent lookups for other servers.
class CachedServerDiscovery final
{
public:
    // `now_ms` is the source of wall-clock milliseconds used for TTL checks;
    // injectable so unit tests can drive deterministic expiry boundaries. An
    // empty callback is treated as "always 0" (every lookup is a miss).
    CachedServerDiscovery(ServerDiscoveryNetwork& upstream, std::uint64_t ttl_ms,
                          std::function<std::uint64_t()> now_ms);

    CachedServerDiscovery(CachedServerDiscovery const&) = delete;
    auto operator=(CachedServerDiscovery const&) -> CachedServerDiscovery& = delete;
    CachedServerDiscovery(CachedServerDiscovery&&) noexcept = delete;
    auto operator=(CachedServerDiscovery&&) noexcept -> CachedServerDiscovery& = delete;
    ~CachedServerDiscovery() = default;

    // Returns a fresh `ServerDiscoveryResult` for `server_name`, serving from
    // the cache when the entry is within TTL and calling the upstream network
    // (then storing the result) on a miss or stale entry.
    [[nodiscard]] auto discover(std::string_view server_name, std::uint32_t timeout_seconds) -> ServerDiscoveryResult;

    // Exposes the wrapped network so callers that need a raw
    // `ServerDiscoveryNetwork&` (e.g. `fetch_remote_server_keys`) can reach it
    // without a separate handle.
    [[nodiscard]] auto upstream() noexcept -> ServerDiscoveryNetwork&;

private:
    struct Entry final
    {
        ServerDiscoveryResult result{};
        std::uint64_t fetched_at_ms{0U};
    };

    ServerDiscoveryNetwork& upstream_;
    std::uint64_t ttl_ms_;
    std::function<std::uint64_t()> now_ms_;
    std::mutex mutex_{};
    std::unordered_map<std::string, Entry> cache_{};
};

} // namespace merovingian::federation