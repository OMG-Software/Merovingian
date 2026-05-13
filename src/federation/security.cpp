// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/security.hpp"

#include <algorithm>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::federation
{
namespace
{

    [[nodiscard]] auto contains_no_control_or_space(std::string_view value) noexcept -> bool
    {
        for (auto const character : value)
        {
            auto const byte = static_cast<unsigned char>(character);
            if (byte <= 0x20U || byte == 0x7FU)
            {
                return false;
            }
        }

        return true;
    }

    [[nodiscard]] auto starts_with(std::string_view value, std::string_view prefix) noexcept -> bool
    {
        return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
    }

    [[nodiscard]] auto contains_signature_for(std::vector<events::EventSignature> const& signatures,
                                              std::string_view expected_server) noexcept -> bool
    {
        return std::ranges::any_of(signatures, [expected_server](events::EventSignature const& signature) {
            return signature.server_name == expected_server && !signature.key_id.empty() &&
                   !signature.signature.empty();
        });
    }

} // namespace

auto server_name_is_valid(std::string_view server_name) noexcept -> bool
{
    return !server_name.empty() && server_name.size() <= 255U && server_name.find('.') != std::string_view::npos &&
           contains_no_control_or_space(server_name);
}

auto ip_address_is_private_or_loopback(std::string_view address) noexcept -> bool
{
    return address == "localhost" || address == "::1" || starts_with(address, "127.") || starts_with(address, "10.") ||
           starts_with(address, "192.168.") || starts_with(address, "169.254.") || starts_with(address, "fc") ||
           starts_with(address, "fd") ||
           (starts_with(address, "172.") && address.size() >= 6U && address[4] >= '1' && address[4] <= '3');
}

auto federation_discovery_policy(RemoteServerRecord const& remote) -> FederationDiscoveryDecision
{
    if (!server_name_is_valid(remote.server_name))
    {
        return {false, "invalid remote server name"};
    }
    if (remote.resolved_host.empty())
    {
        return {false, "remote host is unresolved"};
    }
    if (!remote.well_known_host.empty() && remote.well_known_host != remote.resolved_host)
    {
        return {false, "well-known host and resolved host mismatch"};
    }
    if (remote.resolved_addresses.empty())
    {
        return {false, "remote addresses are unresolved"};
    }
    for (auto const& address : remote.resolved_addresses)
    {
        if (ip_address_is_private_or_loopback(address))
        {
            return {false, "remote address is private or loopback"};
        }
    }
    if (!remote.tls_required)
    {
        return {false, "federation requires TLS"};
    }

    return {true, {}};
}

auto verify_federation_request_signature(FederationRequestSignature const& signature) -> FederationVerificationDecision
{
    if (!server_name_is_valid(signature.origin))
    {
        return {false, "invalid request origin"};
    }
    if (signature.key_id.empty() || signature.signature.empty())
    {
        return {false, "missing request signature"};
    }
    if (!signature.canonical_json_verified)
    {
        return {false, "canonical JSON signature verification required"};
    }

    return {true, {}};
}

auto verify_federation_event_signatures(std::vector<events::EventSignature> const& signatures,
                                        std::string_view expected_server) -> FederationVerificationDecision
{
    if (!server_name_is_valid(expected_server))
    {
        return {false, "invalid expected event signer"};
    }
    if (!contains_signature_for(signatures, expected_server))
    {
        return {false, "missing event signature for expected server"};
    }

    return {true, {}};
}

auto federation_remote_rate_limit() noexcept -> http::RateLimitPolicy
{
    return {120U, 60U};
}

auto remote_trust_policy(RemoteTrustState state) -> RemoteTrustDecision
{
    if (state.quarantined)
    {
        return {false, false, "remote server is quarantined"};
    }
    if (state.circuit_open)
    {
        return {false, true, "remote circuit breaker is open"};
    }
    if (state.reputation_score < 25U)
    {
        return {false, true, "remote reputation is too low"};
    }
    if (state.consecutive_failures >= 3U)
    {
        return {false, true, "remote backoff required"};
    }

    return {true, false, {}};
}

auto federation_security_boundary_notes() -> std::vector<std::string>
{
    return {
        "SSRF boundary: never connect to loopback, link-local, private, or unique-local remote addresses discovered "
        "through federation resolution.",
        "DNS rebinding boundary: bind the validated address set to the outbound request and reject host/address drift "
        "between discovery and connect.",
        "Trust boundary: request signatures, event signatures, remote rate limits, backoff, circuit breakers, "
        "reputation, and quarantine must be evaluated before accepting federation traffic.",
    };
}

} // namespace merovingian::federation
