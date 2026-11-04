// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::federation
{

struct WellKnownServerResult final
{
    bool found{false};
    bool ok{false};
    std::string body{};
    std::string reason{};
};

// ADR-0483: a `/.well-known/matrix/server` fetch follows at most this many redirects. Spec, "Resolving server names"
// step 3: "30x redirects should be followed, however redirection loops should be avoided."
inline constexpr auto well_known_max_redirects = std::uint32_t{4U};

// One request of the well-known fetch, as the transport answered it. `transport_ok` is false when no HTTP answer
// was obtained (connection, TLS, timeout, size). A 3xx answer carries its `Location` header in `location`.
struct WellKnownHopResponse final
{
    bool transport_ok{false};
    std::uint16_t status{0U};
    std::string location{};
    std::string body{};
    std::string error{};
};

// Performs one GET of `url` (an https URL already checked), connecting only to `pinned_addresses`, within
// `timeout_seconds`. It never follows a redirect itself.
using WellKnownHopFetcher = std::function<WellKnownHopResponse(
    std::string const& url, std::vector<std::string> const& pinned_addresses, std::uint32_t timeout_seconds)>;

struct SrvRecord final
{
    std::string target{};
    std::uint16_t port{8448U};
    std::uint16_t priority{0U};
    std::uint16_t weight{0U};
};

// Parses SRV records from the answer section of a raw DNS response message (as
// produced by res_query). Portable across resolver implementations — it does not
// use the BIND ns_* parser API, which is absent on some platforms (e.g. OpenBSD).
// The message bytes are untrusted: the parser is fully bounds-checked and never
// reads past `message_length`. Exposed for unit testing.
[[nodiscard]] auto parse_srv_records(unsigned char const* message, int message_length) -> std::vector<SrvRecord>;

struct ResolvedAddressSet final
{
    bool ok{false};
    std::vector<std::string> addresses{};
    std::string reason{};
};

struct ServerDiscoveryResult final
{
    std::string server_name{};
    std::string well_known_host{};
    std::string resolved_host{};
    // M-02: the name the destination's TLS certificate must be valid for, and
    // the name to send as SNI and in the Host header. This is NOT always
    // resolved_host: when discovery went through an SRV record, resolved_host is
    // the SRV *target*, and the spec is explicit that the certificate must still
    // match the original hostname (or the well-known delegated hostname), never
    // the SRV target — see server-server-api.md steps 4 and 5, and the section
    // "The reasons we require <hostname> rather than <delegated_hostname> for
    // SRV delegation are". Honouring the SRV target instead would let anyone who
    // can forge an unsigned DNS response redirect a server to a host that proves
    // an identity of its own choosing.
    //
    // Callers building an outbound URL must use THIS as the URL host, and pass
    // pinned_addresses to CURLOPT_RESOLVE so the connection still lands on the
    // resolved target. That keeps SNI, Host and certificate validation on the
    // authoritative name while the packets go where discovery said.
    std::string tls_server_name{};
    std::uint16_t resolved_port{8448U};
    std::vector<std::string> pinned_addresses{};
    bool tls_required{true};
    bool discovery_allowed{false};
    std::string reason{};
};

struct FederationDestination final
{
    std::string server_name{};
    std::uint64_t retry_after_ts{0U};
    std::uint64_t last_success_ts{0U};
    std::uint32_t consecutive_failures{0U};
    std::string state{"idle"};
};

class ServerDiscoveryNetwork
{
public:
    explicit ServerDiscoveryNetwork(std::vector<std::string> denied_ip_ranges = {},
                                    std::vector<std::string> allowed_private_ip_ranges = {})
        : denied_ip_ranges_{std::move(denied_ip_ranges)}
        , allowed_private_ip_ranges_{std::move(allowed_private_ip_ranges)}
    {
    }

    // Immutable operator policy shared by every cached/uncached discovery path.
    [[nodiscard]] auto denied_ip_ranges() const noexcept -> std::vector<std::string> const&
    {
        return denied_ip_ranges_;
    }

    // security.federation.allow_private_ip_ranges (ADR-0231). Applied by
    // discover_server, well-known fetches and the cache, which only federation
    // uses; resolve_federation_destination applies it only when the caller
    // passes it, so URL preview sharing this network never gets it.
    [[nodiscard]] auto allowed_private_ip_ranges() const noexcept -> std::vector<std::string> const&
    {
        return allowed_private_ip_ranges_;
    }
    virtual ~ServerDiscoveryNetwork() = default;

    ServerDiscoveryNetwork(ServerDiscoveryNetwork const&) = delete;
    auto operator=(ServerDiscoveryNetwork const&) -> ServerDiscoveryNetwork& = delete;
    ServerDiscoveryNetwork(ServerDiscoveryNetwork&&) noexcept = delete;
    auto operator=(ServerDiscoveryNetwork&&) noexcept -> ServerDiscoveryNetwork& = delete;

    [[nodiscard]] virtual auto fetch_well_known(std::string_view server_name, std::uint32_t timeout_seconds)
        -> WellKnownServerResult = 0;
    [[nodiscard]] virtual auto lookup_srv(std::string_view service_name) -> std::vector<SrvRecord> = 0;
    [[nodiscard]] virtual auto lookup_addresses(std::string_view host, std::uint16_t port) -> ResolvedAddressSet = 0;

private:
    std::vector<std::string> denied_ip_ranges_{};
    std::vector<std::string> allowed_private_ip_ranges_{};
};

// Fetches `https://<server_name>/.well-known/matrix/server`, following redirects (ADR-0483): at most
// `well_known_max_redirects` of them, each target an absolute https URL, resolved and refused unless every address is
// allowed (the network's deny-list and private-range allowance, exactly as for the first request) before `fetch_hop` is
// asked to connect to those addresses only, a URL already visited ends the chain as a loop, and `timeout_seconds` is
// one deadline for all the hops together. `found` is true when a 200 document was obtained; `ok` is false when the
// fetch itself failed or was refused (a 200 and a plain "not there" answer are both ok).
[[nodiscard]] auto fetch_well_known_following_redirects(std::string_view server_name, std::uint32_t timeout_seconds,
                                                         ServerDiscoveryNetwork& network,
                                                         WellKnownHopFetcher const& fetch_hop) -> WellKnownServerResult;

// Test-only opt-in token for the well-known delegation overload below.
//
// Security (audit M-06, 2026-09): that overload resolves through an internal
// literal network whose address lookup returns the documentation address
// 203.0.113.10 for every non-numeric host. It performs no DNS resolution and
// therefore applies none of the real SSRF address checks that a live lookup
// feeds, so it must never be reachable from a production federation path. The
// explicit default constructor means the token cannot be materialised from a
// bare `{}`; every use is a deliberate, greppable opt-in, and a production call
// site written against the old two-argument signature fails to compile.
struct LiteralDiscoveryOptIn final
{
    explicit LiteralDiscoveryOptIn() = default;
};

[[nodiscard]] auto discover_server(LiteralDiscoveryOptIn, std::string_view server_name,
                                   std::string_view well_known_server) -> ServerDiscoveryResult;
[[nodiscard]] auto discover_server(std::string_view server_name, ServerDiscoveryNetwork& network,
                                   std::uint32_t timeout_seconds, std::vector<std::string> const& denied_ranges = {})
    -> ServerDiscoveryResult;
[[nodiscard]] auto discover_server(std::string_view server_name) -> ServerDiscoveryResult;

// Validates that the resolved federation destination is acceptable for the
// original server name from a TLS-certificate-identity perspective. This is
// a logical pre-check, not a live TLS handshake; callers use it before
// connecting to avoid routing a request to a host whose certificate could not
// validly cover the server name.
struct FederationTlsOriginDecision final
{
    bool valid{false};
    std::string reason{};
};

[[nodiscard]] auto validate_federation_tls_origin(std::string_view server_name,
                                                  ServerDiscoveryResult const& discovery) noexcept
    -> FederationTlsOriginDecision;

// Resolves a host:port pair for an outbound federation HTTPS request in an
// SSRF-safe way. Rejects private/loopback IP literals and hosts whose
// resolved addresses include private/loopback space. The returned
// ServerDiscoveryResult carries pinned addresses suitable for libcurl's
// CURLOPT_RESOLVE. Used by callers that need to pin addresses before
// connecting, such as media redirect following.
//
// `allowed_private_ranges` is passed only by federation discovery (ADR-0231);
// the network's own allowance is deliberately not read here.
[[nodiscard]] auto resolve_federation_destination(std::string_view host, std::uint16_t port,
                                                  ServerDiscoveryNetwork& network,
                                                  std::vector<std::string> const& denied_ranges = {},
                                                  std::vector<std::string> const& allowed_private_ranges = {})
    -> ServerDiscoveryResult;

// Creates a production ServerDiscoveryNetwork backed by real DNS and
// HTTP well-known lookups. Used by start_runtime to wire the remote key
// resolver and outbound membership fetch paths.
[[nodiscard]] auto make_system_server_discovery_network(std::vector<std::string> denied_ranges = {},
                                                        std::vector<std::string> allowed_private_ranges = {})
    -> std::unique_ptr<ServerDiscoveryNetwork>;

} // namespace merovingian::federation
