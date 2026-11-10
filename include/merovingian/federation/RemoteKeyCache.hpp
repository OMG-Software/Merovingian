// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/federation/FederationKeyRecord.hpp"
#include "merovingian/federation/KeyMirrorRefresh.hpp"
#include "merovingian/federation/RemoteKeyFetchResult.hpp"
#include "merovingian/federation/RemoteKeyResponse.hpp"
#include "merovingian/federation/ServerDiscoveryNetwork.hpp"
#include "merovingian/federation/ServerDiscoveryResult.hpp"
#include "merovingian/federation/InboundRequestProviders.hpp"
#include "merovingian/http/OutboundClient.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

// Parses and self-verifies a canonical server-key response body. Used by both
// the live outbound fetcher and unit tests that drive the verifier directly.
[[nodiscard]] auto parse_and_verify_remote_key_response(std::string_view body, std::string_view expected_server_name)
    -> RemoteKeyFetchResult;

// Fetches GET /_matrix/key/v2/server from the remote, verifies the
// self-signature, and returns the parsed key set. Discovery and address
// pinning go through the same SSRF policy enforced by the federation
// outbound path.
[[nodiscard]] auto fetch_remote_server_keys(http::OutboundClient& client, ServerDiscoveryNetwork& network,
                                            std::string_view server_name, std::uint32_t timeout_seconds)
    -> RemoteKeyFetchResult;

class CachedServerDiscovery;

// As above, but server-name resolution goes through a TTL-bounded
// `CachedServerDiscovery` so repeated key fetches for the same server skip the
// .well-known + SRV + DNS cascade.
[[nodiscard]] auto fetch_remote_server_keys(http::OutboundClient& client, CachedServerDiscovery& discovery,
                                            std::string_view server_name, std::uint32_t timeout_seconds)
    -> RemoteKeyFetchResult;

// Refresh threshold helper. A remote key needs refresh when the current
// timestamp is at or past `valid_until_ts`, or within a small skew window
// before expiry so verifications never trip on a key that is about to expire.
[[nodiscard]] auto remote_key_needs_refresh(std::uint64_t valid_until_ts, std::uint64_t now_ts) noexcept -> bool;

// Whether a cached key may be used without fetching again: a current key until it is within the refresh
// slack of its expiry, a retired key (old_verify_keys) always, because it can never become current and
// its validity is judged per event against `expired_ts`.
[[nodiscard]] auto cached_remote_key_usable(FederationKeyRecord const& key, std::uint64_t now_ts) noexcept -> bool;

// Persists every verify key in the response, fetched at `fetched_at_ms`, under
// `database::PersistentServerSigningKey`. Each key's valid_until_ts is stored
// as the lesser of the published value and `fetched_at_ms` + 7 days
// (rooms/v5.md, "Signing key validity period"). Each old_verify_keys entry is
// stored as a retired row: `expired_ts` capped at `fetched_at_ms`, and
// `valid_until_ts` equal to it. Retirement is one way and the earliest expiry
// wins (store_server_signing_key): a key later listed under verify_keys stays
// retired, and one a response now lists under old_verify_keys is retired at once. Returns false if any single
// key fails to persist; the caller is expected to log and continue.
[[nodiscard]] auto cache_remote_server_keys(database::PersistentStore& store, RemoteKeyResponse const& response,
                                            std::uint64_t fetched_at_ms) -> bool;

// Looks up a cached verify key by (server_name, key_id), returning the
// federation-shaped key record consumed by request and PDU verification.
[[nodiscard]] auto find_cached_remote_key(database::PersistentStore const& store, std::string_view server_name,
                                          std::string_view key_id) -> std::optional<FederationKeyRecord>;

// FED-1 (ADR-0083): returns this server's own signing key `key_id` for
// `own_server_name`, read only from rows that hold a secret — the keys this
// server generated, current and retired. A row without a secret under our own
// name is a copy obtained from elsewhere and is never returned. Never touches
// the network.
[[nodiscard]] auto find_own_server_signing_key(database::PersistentStore const& store, std::string_view own_server_name,
                                               std::string_view key_id) -> std::optional<FederationKeyRecord>;

// Loads the first cached key for a server (any key_id). Used at request time
// when only the server_name is known and the request key_id can then be
// matched against the cached set.
[[nodiscard]] auto find_any_cached_remote_key(database::PersistentStore const& store, std::string_view server_name)
    -> std::optional<FederationKeyRecord>;

// Source of milliseconds-since-epoch for cache-freshness checks. Injectable so
// tests can drive deterministic refresh boundaries.
using RemoteKeyClock = std::function<std::uint64_t()>;

// Composes the lookup/fetch/verify/cache flow into a single resolver suitable
// for `FederationRuntimeState::remote_key_resolver`. Lookups hit the
// persistent cache first; misses or near-expiry entries trigger an outbound
// fetch, which is verified and returned. Caching the fetched key is
// best-effort: a federation worker cannot write the cache, so the fetched key
// is returned whether or not the write succeeds (ADR-0238).
//
// `own_server_name` is this server's name (FED-1, ADR-0083). A lookup for it
// never goes to the network and never writes the cache: it is answered only
// from this server's own secret-holding signing-key rows (see
// find_own_server_signing_key), and fails when the key ID is not one of them.
// Empty means no own name is known (tests of remote behaviour only).
[[nodiscard]] auto make_persistent_remote_key_resolver(database::PersistentStore& store, http::OutboundClient& client,
                                                       ServerDiscoveryNetwork& network, std::uint32_t timeout_seconds,
                                                       RemoteKeyClock now_ms, std::string_view own_server_name = {},
                                                       KeyMirrorRefresh mirror_refresh = KeyMirrorRefresh::never)
    -> RemoteKeyResolver;

// As above, but both the resolver's own discovery lookup and the fetch's
// internal lookup go through a TTL-bounded `CachedServerDiscovery`, so cache
// hits pay no DNS cascade and a miss pays it once for both.
[[nodiscard]] auto make_persistent_remote_key_resolver(database::PersistentStore& store, http::OutboundClient& client,
                                                       CachedServerDiscovery& discovery, std::uint32_t timeout_seconds,
                                                       RemoteKeyClock now_ms, std::string_view own_server_name = {},
                                                       KeyMirrorRefresh mirror_refresh = KeyMirrorRefresh::never)
    -> RemoteKeyResolver;

// A resolver's two network steps: resolving a server name to a destination,
// and fetching and self-verifying the server's published keys.
using RemoteKeyDiscoverFn = std::function<ServerDiscoveryResult(std::string_view, std::uint32_t)>;
using RemoteKeyFetchFn = std::function<RemoteKeyFetchResult(http::OutboundClient&, std::string_view, std::uint32_t)>;

// As above, with the network steps supplied by the caller; the two overloads
// above bind them to a discovery network or cache. Lets tests drive the
// resolver's cache and trust decisions without a live network.
[[nodiscard]] auto make_remote_key_resolver(database::PersistentStore& store, http::OutboundClient& client,
                                            std::uint32_t timeout_seconds, RemoteKeyClock now_ms,
                                            RemoteKeyDiscoverFn discover, RemoteKeyFetchFn fetch_keys,
                                            std::string_view own_server_name = {},
                                            KeyMirrorRefresh mirror_refresh = KeyMirrorRefresh::never)
    -> RemoteKeyResolver;

} // namespace merovingian::federation
