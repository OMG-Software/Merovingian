// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/events/event.hpp"
#include "merovingian/http/rate_limit.hpp"

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

struct RemoteTrustState final
{
    std::uint32_t consecutive_failures{0U};
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
[[nodiscard]] auto federation_discovery_policy(RemoteServerRecord const& remote) -> FederationDiscoveryDecision;
[[nodiscard]] auto verify_federation_request_signature(FederationRequestSignature const& signature)
    -> FederationVerificationDecision;
[[nodiscard]] auto verify_federation_event_signatures(
    std::vector<events::EventSignature> const& signatures,
    std::string_view expected_server
) -> FederationVerificationDecision;
[[nodiscard]] auto federation_remote_rate_limit() noexcept -> http::RateLimitPolicy;
[[nodiscard]] auto remote_trust_policy(RemoteTrustState state) -> RemoteTrustDecision;
[[nodiscard]] auto federation_security_boundary_notes() -> std::vector<std::string>;

} // namespace merovingian::federation
