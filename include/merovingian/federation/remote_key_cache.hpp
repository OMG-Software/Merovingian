// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/persistent_store.hpp"
#include "merovingian/federation/inbound_request.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

// One verify key entry returned by GET /_matrix/key/v2/server. Mirrors the
// per-entry shape from the canonical Matrix server-key response.
struct RemoteVerifyKey final
{
    std::string key_id{};
    std::string public_key_base64{};
};

// Parsed and self-verified result of fetching a remote server's keys.
struct RemoteKeyResponse final
{
    std::string server_name{};
    std::uint64_t valid_until_ts{0U};
    std::vector<RemoteVerifyKey> verify_keys{};
};

struct RemoteKeyFetchResult final
{
    bool ok{false};
    RemoteKeyResponse response{};
    std::string reason{};
};

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

// Refresh threshold helper. A remote key needs refresh when the current
// timestamp is at or past `valid_until_ts`, or within a small skew window
// before expiry so verifications never trip on a key that is about to expire.
[[nodiscard]] auto remote_key_needs_refresh(std::uint64_t valid_until_ts, std::uint64_t now_ts) noexcept -> bool;

// Persists every verify key in the response under
// `database::PersistentServerSigningKey`. Returns false if any single key
// fails to persist; the caller is expected to log and continue.
[[nodiscard]] auto cache_remote_server_keys(database::PersistentStore& store, RemoteKeyResponse const& response) -> bool;

// Looks up a cached verify key by (server_name, key_id), returning the
// federation-shaped key record consumed by request and PDU verification.
[[nodiscard]] auto find_cached_remote_key(database::PersistentStore const& store, std::string_view server_name,
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
// fetch which is verified and stored before being returned.
[[nodiscard]] auto make_persistent_remote_key_resolver(database::PersistentStore& store, http::OutboundClient& client,
                                                       ServerDiscoveryNetwork& network, std::uint32_t timeout_seconds,
                                                       RemoteKeyClock now_ms) -> RemoteKeyResolver;

} // namespace merovingian::federation
