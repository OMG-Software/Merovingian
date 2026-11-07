// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

#include "merovingian/federation/FederationDestination.hpp"       // split-shim
#include "merovingian/federation/FederationTlsOriginDecision.hpp" // split-shim
#include "merovingian/federation/LiteralDiscoveryOptIn.hpp"       // split-shim
#include "merovingian/federation/ResolvedAddressSet.hpp"          // split-shim
#include "merovingian/federation/ServerDiscoveryNetwork.hpp"      // split-shim
#include "merovingian/federation/ServerDiscoveryResult.hpp"       // split-shim
#include "merovingian/federation/SrvRecord.hpp"                   // split-shim
#include "merovingian/federation/WellKnownHopResponse.hpp"        // split-shim
#include "merovingian/federation/WellKnownServerResult.hpp"       // split-shim

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace merovingian::federation
{

// ADR-0483: a `/.well-known/matrix/server` fetch follows at most this many redirects. Spec, "Resolving server names"
// step 3: "30x redirects should be followed, however redirection loops should be avoided."
inline constexpr auto well_known_max_redirects = std::uint32_t{4U};

// Performs one GET of `url` (an https URL already checked), connecting only to `pinned_addresses`, within
// `timeout_seconds`. It never follows a redirect itself.
using WellKnownHopFetcher = std::function<WellKnownHopResponse(
    std::string const& url, std::vector<std::string> const& pinned_addresses, std::uint32_t timeout_seconds)>;

// Parses SRV records from the answer section of a raw DNS response message (as
// produced by res_query). Portable across resolver implementations — it does not
// use the BIND ns_* parser API, which is absent on some platforms (e.g. OpenBSD).
// The message bytes are untrusted: the parser is fully bounds-checked and never
// reads past `message_length`. Exposed for unit testing.
[[nodiscard]] auto parse_srv_records(unsigned char const* message, int message_length) -> std::vector<SrvRecord>;

// Fetches `https://<server_name>/.well-known/matrix/server`, following redirects (ADR-0483): at most
// `well_known_max_redirects` of them, each target an absolute https URL, resolved and refused unless every address is
// allowed (the network's deny-list and private-range allowance, exactly as for the first request) before `fetch_hop` is
// asked to connect to those addresses only, a URL already visited ends the chain as a loop, and `timeout_seconds` is
// one deadline for all the hops together. `found` is true when a 200 document was obtained; `ok` is false when the
// fetch itself failed or was refused (a 200 and a plain "not there" answer are both ok).
[[nodiscard]] auto fetch_well_known_following_redirects(std::string_view server_name, std::uint32_t timeout_seconds,
                                                         ServerDiscoveryNetwork& network,
                                                         WellKnownHopFetcher const& fetch_hop) -> WellKnownServerResult;

[[nodiscard]] auto discover_server(LiteralDiscoveryOptIn, std::string_view server_name,
                                   std::string_view well_known_server) -> ServerDiscoveryResult;
[[nodiscard]] auto discover_server(std::string_view server_name, ServerDiscoveryNetwork& network,
                                   std::uint32_t timeout_seconds, std::vector<std::string> const& denied_ranges = {})
    -> ServerDiscoveryResult;
[[nodiscard]] auto discover_server(std::string_view server_name) -> ServerDiscoveryResult;

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
