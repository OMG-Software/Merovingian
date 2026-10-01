// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/security.hpp"

#include "merovingian/observability/logger.hpp"
#include "merovingian/observability/observability.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

namespace merovingian::federation
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("federation_security", event, fields, severity);
    }

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

    // IPv4 non-public ranges used for SSRF rejection. Includes loopback (127/8),
    // RFC 1918 (10/8, 172.16/12, 192.168/16), link-local (169.254/16), CGNAT
    // (100.64/10), multicast (224/4), reserved/future-use (240/4), and the
    // unspecified address 0.0.0.0.
    [[nodiscard]] auto ipv4_is_private_or_loopback(std::uint32_t address) noexcept -> bool
    {
        auto const first = static_cast<std::uint8_t>((address >> 24U) & 0xFFU);
        auto const second = static_cast<std::uint8_t>((address >> 16U) & 0xFFU);
        if (first == 0U || first == 10U || first == 127U || (first == 169U && second == 254U) ||
            (first == 172U && second >= 16U && second <= 31U) || (first == 192U && second == 168U))
        {
            return true;
        }
        // CGNAT (RFC 6598) and multicast/reserved space.
        if (first == 100U && second >= 64U && second <= 127U)
        {
            return true;
        }
        if (first >= 224U)
        {
            return true;
        }
        return false;
    }

    // IPv6 non-public ranges used for SSRF rejection. Includes unspecified (::/128),
    // loopback (::1/128), ULA (fc00::/7), link-local (fe80::/10), NAT64 well-known
    // prefix (64:ff9b::/96), multicast (ff00::/8), and IPv4-mapped variants of the
    // IPv4 ranges above.
    [[nodiscard]] auto ipv6_is_private_or_loopback(in6_addr const& address) noexcept -> bool
    {
        auto const* bytes = address.s6_addr;
        auto const is_unspecified = std::all_of(bytes, bytes + 16U, [](auto byte) noexcept {
            return byte == std::uint8_t{0U};
        });
        auto const is_loopback = std::all_of(bytes, bytes + 15U,
                                             [](auto byte) noexcept {
                                                 return byte == std::uint8_t{0U};
                                             }) &&
                                 bytes[15] == std::uint8_t{1U};
        auto const is_unique_local = (bytes[0] & 0xFEU) == 0xFCU;
        auto const is_link_local = bytes[0] == 0xFEU && (bytes[1] & 0xC0U) == 0x80U;
        // Well-known NAT64 prefix 64:ff9b::/96.
        auto const is_nat64 = bytes[0] == 0x00U && bytes[1] == 0x64U && bytes[2] == 0xFFU && bytes[3] == 0x9BU &&
                              std::all_of(bytes + 4U, bytes + 8U, [](auto byte) noexcept {
                                  return byte == std::uint8_t{0U};
                              });
        auto const is_multicast = bytes[0] == 0xFFU;
        auto const is_v4_mapped = std::all_of(bytes, bytes + 10U,
                                              [](auto byte) noexcept {
                                                  return byte == std::uint8_t{0U};
                                              }) &&
                                  bytes[10] == 0xFFU && bytes[11] == 0xFFU;
        auto const mapped_v4 = (static_cast<std::uint32_t>(bytes[12]) << 24U) |
                               (static_cast<std::uint32_t>(bytes[13]) << 16U) |
                               (static_cast<std::uint32_t>(bytes[14]) << 8U) | static_cast<std::uint32_t>(bytes[15]);
        return is_unspecified || is_loopback || is_unique_local || is_link_local || is_nat64 || is_multicast ||
               (is_v4_mapped && ipv4_is_private_or_loopback(mapped_v4));
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

auto ip_address_is_valid(std::string_view address) noexcept -> bool
{
    auto const text = std::string{address};
    auto v4 = in_addr{};
    auto v6 = in6_addr{};
    return ::inet_pton(AF_INET, text.c_str(), &v4) == 1 || ::inet_pton(AF_INET6, text.c_str(), &v6) == 1;
}

auto ip_address_is_private_or_loopback(std::string_view address) noexcept -> bool
{
    auto const text = std::string{address};
    auto v4 = in_addr{};
    if (::inet_pton(AF_INET, text.c_str(), &v4) == 1)
    {
        return ipv4_is_private_or_loopback(ntohl(v4.s_addr));
    }
    auto v6 = in6_addr{};
    if (::inet_pton(AF_INET6, text.c_str(), &v6) == 1)
    {
        return ipv6_is_private_or_loopback(v6);
    }
    // Fallback for inputs inet_pton cannot parse as a literal IP (e.g. the
    // hostname "localhost"). The numeric private/loopback/reserved/CGNAT ranges
    // are handled exactly by the inet_pton path above; a string-prefix guess
    // for 172. or 100. would both over-block public addresses and under-block
    // the intended ranges, so they are intentionally omitted.
    return address == "localhost" || starts_with(address, "127.") || starts_with(address, "10.") ||
           starts_with(address, "192.168.") || starts_with(address, "169.254.") || starts_with(address, "fc") ||
           starts_with(address, "fd");
}

auto address_set_allowed(std::vector<std::string> const& addresses) noexcept -> bool
{
    return !addresses.empty() && std::ranges::none_of(addresses, [](std::string const& address) {
        return ip_address_is_private_or_loopback(address);
    });
}

auto federation_discovery_policy(RemoteServerRecord const& remote) -> FederationDiscoveryDecision
{
    if (!server_name_is_valid(remote.server_name))
    {
        log_diagnostic("discovery.rejected", {
                                                 {"server_name", remote.server_name,           false},
                                                 {"reason",      "invalid remote server name", false}
        });
        return {false, "invalid remote server name"};
    }
    if (remote.resolved_host.empty())
    {
        log_diagnostic("discovery.rejected",
                       {
                           {"server_name", remote.server_name,          false},
                           {"reason",      "remote host is unresolved", false}
        });
        return {false, "remote host is unresolved"};
    }
    if (!remote.well_known_host.empty() && remote.well_known_host != remote.resolved_host)
    {
        log_diagnostic("discovery.rejected", {
                                                 {"server_name",     remote.server_name,                           false},
                                                 {"well_known_host", remote.well_known_host,                       false},
                                                 {"resolved_host",   remote.resolved_host,                         false},
                                                 {"reason",          "well-known host and resolved host mismatch", false}
        });
        return {false, "well-known host and resolved host mismatch"};
    }
    if (remote.resolved_addresses.empty())
    {
        log_diagnostic("discovery.rejected", {
                                                 {"server_name", remote.server_name,                false},
                                                 {"reason",      "remote addresses are unresolved", false}
        });
        return {false, "remote addresses are unresolved"};
    }
    for (auto const& address : remote.resolved_addresses)
    {
        if (ip_address_is_private_or_loopback(address))
        {
            log_diagnostic("discovery.rejected", {
                                                     {"server_name", remote.server_name,                      false},
                                                     {"address",     address,                                 false},
                                                     {"reason",      "remote address is private or loopback", false}
            });
            return {false, "remote address is private or loopback"};
        }
    }
    if (!remote.tls_required)
    {
        log_diagnostic("discovery.rejected",
                       {
                           {"server_name", remote.server_name,        false},
                           {"reason",      "federation requires TLS", false}
        });
        return {false, "federation requires TLS"};
    }

    return {true, {}};
}

auto verify_federation_request_signature(FederationRequestSignature const& signature) -> FederationVerificationDecision
{
    if (!server_name_is_valid(signature.origin))
    {
        log_diagnostic("request_signature.rejected",
                       {
                           {"origin", signature.origin,         false},
                           {"reason", "invalid request origin", false}
        });
        return {false, "invalid request origin"};
    }
    if (signature.key_id.empty() || signature.signature.empty())
    {
        log_diagnostic("request_signature.rejected",
                       {
                           {"origin", signature.origin,            false},
                           {"reason", "missing request signature", false}
        });
        return {false, "missing request signature"};
    }
    if (!signature.canonical_json_verified)
    {
        log_diagnostic("request_signature.rejected",
                       {
                           {"origin", signature.origin,                                 false},
                           {"reason", "canonical JSON signature verification required", false}
        });
        return {false, "canonical JSON signature verification required"};
    }

    return {true, {}};
}

auto verify_federation_event_signatures(std::vector<events::EventSignature> const& signatures,
                                        std::string_view expected_server) -> FederationVerificationDecision
{
    if (!server_name_is_valid(expected_server))
    {
        log_diagnostic("event_signatures.rejected", {
                                                        {"expected_server", std::string{expected_server},    false},
                                                        {"reason",          "invalid expected event signer", false}
        });
        return {false, "invalid expected event signer"};
    }
    if (!contains_signature_for(signatures, expected_server))
    {
        log_diagnostic("event_signatures.rejected",
                       {
                           {"expected_server", std::string{expected_server},                  false},
                           {"reason",          "missing event signature for expected server", false}
        });
        return {false, "missing event signature for expected server"};
    }

    return {true, {}};
}

auto federation_remote_rate_limit() noexcept -> http::RateLimitPolicy
{
    return {120U, 60U};
}

namespace
{

    [[nodiscard]] auto backoff_has_decayed(RemoteTrustState const& state,
                                           std::chrono::steady_clock::time_point now) noexcept -> bool
    {
        // An unset timestamp cannot be aged, so it never decays.
        return state.last_failure_at != std::chrono::steady_clock::time_point{} &&
               now - state.last_failure_at >= remote_backoff_decay_window;
    }

} // namespace

auto record_remote_trust_failure(RemoteTrustState& state, std::chrono::steady_clock::time_point now) noexcept -> void
{
    if (backoff_has_decayed(state, now))
    {
        state.consecutive_failures = 0U;
    }
    if (state.consecutive_failures < std::numeric_limits<std::uint32_t>::max())
    {
        ++state.consecutive_failures;
    }
    state.last_failure_at = now;
}

auto remote_trust_policy(RemoteTrustState state, std::chrono::steady_clock::time_point now) -> RemoteTrustDecision
{
    if (state.quarantined)
    {
        log_diagnostic("trust.rejected", {
                                             {"reason", "remote server is quarantined", false}
        });
        return {false, false, "remote server is quarantined"};
    }
    if (state.circuit_open)
    {
        log_diagnostic("trust.rejected", {
                                             {"reason", "remote circuit breaker is open", false}
        });
        return {false, true, "remote circuit breaker is open"};
    }
    if (state.reputation_score < 25U)
    {
        log_diagnostic("trust.rejected", {
                                             {"reputation_score", std::to_string(state.reputation_score), false},
                                             {"reason",           "remote reputation is too low",         false}
        });
        return {false, true, "remote reputation is too low"};
    }
    if (state.consecutive_failures >= 3U && !backoff_has_decayed(state, now))
    {
        log_diagnostic("trust.rejected",
                       {
                           {"consecutive_failures", std::to_string(state.consecutive_failures), false},
                           {"reason",               "remote backoff required",                  false}
        });
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
