// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/events/event.hpp"
#include "merovingian/http/rate_limit.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{

struct RemoteServerRecord final
{
    std::string server_name{};
    std::string well_known_host{};
    std::string resolved_host{};
    std::vector<std::string> resolved_addresses{};
    bool tls_required{true};
};

struct FederationDiscoveryDecision final
{
    bool accepted{false};
    std::string reason{};
};

struct FederationRequestSignature final
{
    std::string origin{};
    std::string key_id{};
    std::string signature{};
    bool canonical_json_verified{false};
};

struct FederationVerificationDecision final
{
    bool accepted{false};
    std::string reason{};
};

// Quiet period after which an origin's consecutive-failure backoff lapses. The
// count only ever grows from failures attributable to the origin itself (see
// ADR-0081), so this is a recovery path for a peer that misbehaved, not a
// defence against forged traffic: it bounds how long a real peer stays refused
// after a bad patch, so a backoff can never persist until restart.
inline constexpr auto remote_backoff_decay_window = std::chrono::minutes{5};

struct RemoteTrustState final
{
    std::uint32_t consecutive_failures{0U};
    // When the most recent failure was recorded. A default (epoch) value means
    // "unknown", which never decays: fail closed.
    std::chrono::steady_clock::time_point last_failure_at{};
    std::uint32_t reputation_score{100U};
    bool quarantined{false};
    bool circuit_open{false};
};

struct RemoteTrustDecision final
{
    bool accepted{false};
    bool apply_backoff{false};
    std::string reason{};
};

[[nodiscard]] auto server_name_is_valid(std::string_view server_name) noexcept -> bool;
[[nodiscard]] auto ip_address_is_private_or_loopback(std::string_view address) noexcept -> bool;
// True when the set is non-empty and every address is public (not private,
// loopback, link-local, CGNAT, NAT64, multicast, or reserved). Used by the
// SSRF-safe discovery path to reject a host whose resolution includes any
// non-public address.
[[nodiscard]] auto address_set_allowed(std::vector<std::string> const& addresses) noexcept -> bool;
// Strict syntactic IPv4/IPv6 literal check (via inet_pton). Used to validate
// operator-facing values derived from untrusted headers (e.g. X-Forwarded-For)
// before they are trusted as an effective client address.
[[nodiscard]] auto ip_address_is_valid(std::string_view address) noexcept -> bool;
[[nodiscard]] auto federation_discovery_policy(RemoteServerRecord const& remote) -> FederationDiscoveryDecision;
[[nodiscard]] auto verify_federation_request_signature(FederationRequestSignature const& signature)
    -> FederationVerificationDecision;
[[nodiscard]] auto verify_federation_event_signatures(std::vector<events::EventSignature> const& signatures,
                                                      std::string_view expected_server)
    -> FederationVerificationDecision;
[[nodiscard]] auto federation_remote_rate_limit() noexcept -> http::RateLimitPolicy;
// `now` is a seam for tests; production callers use the default. The
// consecutive-failure backoff is ignored once `remote_backoff_decay_window` has
// elapsed since `last_failure_at`. Quarantine, an open circuit and low
// reputation are operator/administrative states and never decay with time.
[[nodiscard]] auto remote_trust_policy(RemoteTrustState state,
                                       std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now())
    -> RemoteTrustDecision;
// Records one failure attributable to an AUTHENTICATED origin (its signature
// already verified). Never call this for a failed signature check: the claimed
// origin is unauthenticated (ADR-0081). A stale count from before a quiet
// period is discarded first so old failures do not compound with new ones.
auto record_remote_trust_failure(RemoteTrustState& state, std::chrono::steady_clock::time_point now =
                                                              std::chrono::steady_clock::now()) noexcept -> void;
[[nodiscard]] auto federation_security_boundary_notes() -> std::vector<std::string>;

} // namespace merovingian::federation
