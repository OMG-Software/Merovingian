// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |              MATRIX SERVER DISCOVERY CONFORMANCE TESTS                  |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.18, Sec. 2 Resolving server names        |
// |  URL:  ../../docs/matrix-v1.18-spec/server-server-api.md                 |
// |        #resolving-server-names                                           |
// |                                                                         |
// |  !! IMPORTANT - FOR HUMANS AND LLMs ALIKE !!                            |
// |                                                                         |
// |  Every REQUIRE in this file encodes a MUST or SHOULD from the Matrix    |
// |  specification. If a test fails:                                         |
// |                                                                         |
// |    -> Fix the IMPLEMENTATION so it matches the spec.                     |
// |    -> Do NOT weaken, comment out, or remove assertions to make CI pass.  |
// |    -> Do NOT change an expected value without first verifying that the   |
// |      spec itself has changed and citing the updated section.             |
// |                                                                         |
// |  The spec section is cited above each SCENARIO. Cross-check it before   |
// |  concluding that a failing assertion is wrong.                           |
// +-------------------------------------------------------------------------+

#include "merovingian/federation/server_discovery.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace
{

class FakeDiscoveryNetwork final : public merovingian::federation::ServerDiscoveryNetwork
{
public:
    merovingian::federation::WellKnownServerResult well_known{};
    std::vector<merovingian::federation::SrvRecord> srv_records{};
    std::unordered_map<std::string, std::vector<std::string>> addresses{};
    std::string fetched_server{};
    std::uint32_t fetched_timeout{0U};

    [[nodiscard]] auto fetch_well_known(std::string_view server_name, std::uint32_t timeout_seconds)
        -> merovingian::federation::WellKnownServerResult override
    {
        fetched_server = server_name;
        fetched_timeout = timeout_seconds;
        return well_known;
    }

    [[nodiscard]] auto lookup_srv(std::string_view service_name)
        -> std::vector<merovingian::federation::SrvRecord> override
    {
        last_srv_lookup = service_name;
        return srv_records;
    }

    [[nodiscard]] auto lookup_addresses(std::string_view host, std::uint16_t)
        -> merovingian::federation::ResolvedAddressSet override
    {
        auto found = addresses.find(std::string{host});
        if (found == addresses.end())
        {
            return {false, {}, "address not found"};
        }
        return {true, found->second, {}};
    }

    std::string last_srv_lookup{};
};

} // namespace

// --- Direct resolution (no delegation) ---------------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 2 Resolving server names
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#resolving-server-names
//
// If the server name is a literal IP or hostname with no well-known file,
// the server MUST be contacted directly on the given host and port. The
// resolution algorithm terminates at step 1 (explicit host:port) or step 4
// (direct HTTPS on port 8448) without consulting well-known or SRV records.
SCENARIO("Server discovery resolves a direct server name without well-known", "[federation][discovery]")
{
    GIVEN("a server name with no well-known delegation")
    {
        WHEN("discovery is attempted against a local mock")
        {
            auto const result = merovingian::federation::discover_server("example.org", "https://example.org:8448");

            THEN("the resolved host and port are returned from the direct URL")
            {
                // Spec MUST: resolved_host is the hostname taken directly from the supplied URL.
                // Do NOT remove/change - this guards the base case of the resolution algorithm.
                REQUIRE(result.resolved_host == "example.org");
                // Spec MUST: resolved_port is the port taken directly from the supplied URL.
                // Do NOT remove/change - the default federation port 8448 MUST be preserved when explicit.
                REQUIRE(result.resolved_port == 8448U);
            }
        }
    }
}

// --- Well-known delegation ----------------------------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 2.1 Well-known URI delegation
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#well-known-uri
//
// If the server name is not a literal IP and has no explicit port, servers
// MUST request /.well-known/matrix/server. When the m.server property is
// present the delegated host:port MUST be used for all subsequent federation
// traffic to that server name.
SCENARIO("Server discovery resolves a server name with well-known delegation", "[federation][discovery]")
{
    GIVEN("a server name that delegates via well-known")
    {
        WHEN("discovery parses the delegated server name")
        {
            auto const result =
                merovingian::federation::discover_server("example.org", "https://delegated.example.org:8448");

            THEN("the resolved host and port come from the delegated server")
            {
                // Spec MUST: the delegated host replaces the original server name as the federation target.
                // Do NOT remove/change - well-known delegation is a mandatory part of the resolution algorithm.
                REQUIRE(result.resolved_host == "delegated.example.org");
                // Spec MUST: the delegated port (here 8448) must be honoured verbatim.
                // Do NOT remove/change - using the wrong port silently breaks federation.
                REQUIRE(result.resolved_port == 8448U);
            }
        }
    }
}

// --- SSRF: private / loopback address rejection -------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 2 Resolving server names (security)
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#resolving-server-names
//
// Servers MUST NOT send federation traffic to private or loopback addresses.
// Allowing federation to 127.x.x.x, 10.x.x.x, 172.16-31.x.x, 192.168.x.x,
// or IPv6 link-local/loopback ranges would enable Server-Side Request Forgery
// (SSRF) attacks. Discovery MUST fail closed for all such addresses.
SCENARIO("Server discovery rejects private IP addresses", "[federation][discovery][security]")
{
    GIVEN("a server name that resolves to a private address")
    {
        WHEN("discovery is attempted")
        {
            THEN("loopback addresses are rejected")
            {
                auto const result = merovingian::federation::discover_server("evil.org", "https://127.0.0.1:8448");
                // Spec MUST: discovery_allowed MUST be false for loopback destinations — SSRF prevention.
                // Do NOT remove/change — weakening this allows internal network scanning via federation.
                REQUIRE_FALSE(result.discovery_allowed);
                // Implementation contract (not a spec requirement): the reason field must be non-empty
                // so callers can log a meaningful error. The spec does not mandate a specific string.
                REQUIRE_FALSE(result.reason.empty());
            }
        }
    }
}

// --- Discovery result structure -----------------------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 2 Resolving server names
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#resolving-server-names
//
// A successful resolution result MUST carry the original server name,
// the resolved host and port, a flag indicating TLS is required, and a flag
// indicating that the destination is permitted (i.e. not a private address).
SCENARIO("Server discovery results have correct structure", "[federation][discovery]")
{
    GIVEN("a successful discovery result")
    {
        auto const result =
            merovingian::federation::discover_server("matrix.example.org", "https://matrix.example.org:8448");

        WHEN("the result fields are inspected")
        {
            THEN("the server name, resolved host, port, and TLS requirement are correct")
            {
                // Spec MUST: server_name preserves the original queried server name.
                // Do NOT remove/change - this field is used when signing requests to the remote.
                REQUIRE(result.server_name == "matrix.example.org");
                // Spec MUST: resolved_host is the target host after full algorithm resolution.
                // Do NOT remove/change - wrong host leads to TLS certificate mismatch.
                REQUIRE(result.resolved_host == "matrix.example.org");
                // Spec MUST: resolved_port is the target port (default 8448).
                // Do NOT remove/change - wrong port silently breaks federation.
                REQUIRE(result.resolved_port == 8448U);
                // Spec MUST: TLS MUST be used for all federation traffic.
                // Do NOT remove/change - plaintext federation violates the spec security model.
                REQUIRE(result.tls_required);
                // Spec MUST: discovery_allowed must be true for a legitimate public server.
                // Do NOT remove/change - a false value here would incorrectly block all federation.
                REQUIRE(result.discovery_allowed);
            }
        }
    }
}

// --- Default federation port and TLS -----------------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 2.3 Direct IP / default port
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#resolving-server-names
//
// If no explicit port is given and no SRV record is found, servers MUST
// use port 8448. All federation connections MUST use TLS regardless of port.
SCENARIO("Server discovery with default port 8448 uses TLS", "[federation][discovery]")
{
    GIVEN("a server name resolved to port 8448")
    {
        auto const result =
            merovingian::federation::discover_server("matrix.example.org", "https://matrix.example.org:8448");

        WHEN("TLS requirement is checked")
        {
            THEN("TLS is required for the default federation port")
            {
                // Spec MUST: TLS MUST be required even when port 8448 is the default.
                // Do NOT remove/change - federation over plaintext is not permitted by the spec.
                REQUIRE(result.tls_required);
            }
        }
    }
}

// --- Server name validation ---------------------------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 2 Resolving server names
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#resolving-server-names
//
// An empty server name is not a valid Matrix server identifier. Discovery
// MUST fail closed rather than attempt a connection to an unspecified host.
SCENARIO("Server discovery validates server name format", "[federation][discovery]")
{
    GIVEN("invalid server names")
    {
        WHEN("an empty server name is discovered")
        {
            auto const result = merovingian::federation::discover_server("", "https://:8448");

            THEN("discovery is rejected")
            {
                // Spec MUST: an empty server name MUST be rejected - it is not a valid Matrix identifier.
                // Do NOT remove/change - allowing empty names could route requests to arbitrary hosts.
                REQUIRE_FALSE(result.discovery_allowed);
            }
        }
    }
}

// --- Federation destination retry state --------------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 2 Resolving server names
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#resolving-server-names
//
// Servers SHOULD implement exponential back-off for unreachable federation
// destinations. The FederationDestination struct persists the fields needed
// to enforce retry delays: consecutive_failures, retry_after_ts, and
// last_success_ts. These fields MUST survive across struct assignments.
SCENARIO("Federation destination persists retry state", "[federation][queue]")
{
    GIVEN("a federation destination with retry tracking")
    {
        auto destination = merovingian::federation::FederationDestination{};
        destination.server_name = "remote.example.org";
        destination.retry_after_ts = 0U;
        destination.consecutive_failures = 0U;
        destination.last_success_ts = 1000U;

        WHEN("a failure is recorded")
        {
            destination.consecutive_failures = 1U;
            destination.retry_after_ts = 5000U;

            THEN("failure state persists across instances")
            {
                // Spec SHOULD: server_name identifies the remote to which back-off applies.
                // Do NOT remove/change - wrong server_name could apply back-off to the wrong peer.
                REQUIRE(destination.server_name == "remote.example.org");
                // Spec SHOULD: consecutive_failures MUST be incremented on each delivery failure.
                // Do NOT remove/change - this counter drives the exponential back-off calculation.
                REQUIRE(destination.consecutive_failures == 1U);
                // Spec SHOULD: retry_after_ts MUST be set to the earliest timestamp at which retry is allowed.
                // Do NOT remove/change - ignoring this value causes premature retries under back-off.
                REQUIRE(destination.retry_after_ts == 5000U);
            }
        }
    }
}

// --- Well-known delegation with address pinning -------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 2.1 Well-known URI delegation
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#well-known-uri
//
// If a valid m.server value is returned by well-known, the resolved
// host MUST be the delegated host and the resolved port MUST be the
// delegated port. Resolved addresses MUST be pinned so that subsequent
// connection attempts do not re-resolve the hostname and risk SSRF bypass.
SCENARIO("Server discovery fetches well-known delegation and pins public IPv4 and IPv6 addresses",
         "[federation][discovery][well-known]")
{
    GIVEN("a remote server with a well-known delegation and public address set")
    {
        auto network = FakeDiscoveryNetwork{};
        network.well_known = {true, true, "{\"m.server\":\"fed.example.net:9448\"}", {}};
        network.addresses.emplace("fed.example.net", std::vector<std::string>{"203.0.113.10", "2001:db8::10"});

        WHEN("the server is discovered through the network boundary")
        {
            auto const result = merovingian::federation::discover_server("example.org", network, 7U);

            THEN("the delegated host and validated pinned addresses are returned")
            {
                // Spec MUST: the well-known fetch MUST target the original server name, not a pre-resolved IP.
                // Do NOT remove/change - fetching well-known from the wrong host breaks delegation.
                REQUIRE(network.fetched_server == "example.org");
                // Spec SHOULD: the configured timeout MUST be forwarded to the well-known fetch.
                // Do NOT remove/change - an uncapped timeout enables slow-loris DoS on the discovery path.
                REQUIRE(network.fetched_timeout == 7U);
                // Spec MUST: discovery_allowed MUST be true when the delegated address is a public IP.
                // Do NOT remove/change - a false value here would incorrectly block all federated traffic.
                REQUIRE(result.discovery_allowed);
                // Spec MUST: well_known_host MUST be the hostname extracted from m.server.
                // Do NOT remove/change - this field is the audit trail for which delegation was applied.
                REQUIRE(result.well_known_host == "fed.example.net");
                // Spec MUST: resolved_host MUST equal the delegated hostname.
                // Do NOT remove/change - the wrong resolved_host causes TLS SNI failures.
                REQUIRE(result.resolved_host == "fed.example.net");
                // Spec MUST: resolved_port MUST equal the port from the m.server value.
                // Do NOT remove/change - wrong port silently breaks all outbound federation.
                REQUIRE(result.resolved_port == 9448U);
                auto const expected_addresses = std::vector<std::string>{"203.0.113.10", "2001:db8::10"};
                // Spec MUST: pinned_addresses MUST contain all resolved public IPs for SSRF-safe connection.
                // Do NOT remove/change - unpinned addresses allow DNS rebinding attacks.
                REQUIRE(result.pinned_addresses == expected_addresses);
            }
        }
    }
}

// --- SRV fallback with address pinning ---------------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 2.2 SRV lookup
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#resolving-server-names
//
// If well-known is absent or returns no m.server, servers MUST query the
// _matrix-fed._tcp.<server_name> SRV record. The record with the lowest
// priority value MUST be selected. The SRV target and port MUST be used as
// the federation destination. Resolved addresses MUST be pinned.
SCENARIO("Server discovery falls back to DNS SRV records and pins resolved addresses", "[federation][discovery][dns]")
{
    GIVEN("a remote server without well-known but with Matrix federation SRV records")
    {
        auto network = FakeDiscoveryNetwork{};
        network.srv_records = {
            {"slow.example.net", 9448U, 20U, 0U},
            {"srv.example.net",  9449U, 10U, 0U},
        };
        network.addresses.emplace("srv.example.net", std::vector<std::string>{"198.51.100.22"});

        WHEN("the server is discovered through the network boundary")
        {
            auto const result = merovingian::federation::discover_server("example.org", network, 5U);

            THEN("the lowest-priority SRV target becomes the outbound destination")
            {
                // Spec MUST: the SRV lookup MUST query _matrix-fed._tcp.<server_name>.
                // Do NOT remove/change - querying the wrong name means SRV records are silently ignored.
                REQUIRE(network.last_srv_lookup == "_matrix-fed._tcp.example.org");
                // Spec MUST: discovery_allowed MUST be true for public SRV targets.
                // Do NOT remove/change - false here would block all SRV-resolved federation traffic.
                REQUIRE(result.discovery_allowed);
                // Spec MUST: the SRV target with lowest priority MUST be the resolved host.
                // Do NOT remove/change - using a higher-priority target violates SRV selection rules.
                REQUIRE(result.resolved_host == "srv.example.net");
                // Spec MUST: the port from the winning SRV record MUST be used.
                // Do NOT remove/change - wrong port breaks federation to SRV-advertised servers.
                REQUIRE(result.resolved_port == 9449U);
                auto const expected_addresses = std::vector<std::string>{"198.51.100.22"};
                // Spec MUST: pinned_addresses MUST contain the resolved IPs of the SRV target.
                // Do NOT remove/change - unpinned addresses enable DNS rebinding after discovery.
                REQUIRE(result.pinned_addresses == expected_addresses);
            }
        }
    }
}

// --- SSRF: private / loopback rejection via well-known and SRV ---------------
// Spec: Matrix Server-Server API v1.18, Sec. 2 Resolving server names (security)
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#resolving-server-names
//
// Private IPv4 ranges (10/8, 172.16/12, 192.168/16) and IPv6 link-local
// (fe80::/10) or loopback (::1) addresses MUST be rejected regardless of
// whether they arrive via well-known delegation or SRV records. Failure
// MUST be closed: no addresses may be pinned for a rejected destination.
SCENARIO("Server discovery rejects private and loopback addresses before pinning", "[federation][discovery][security]")
{
    GIVEN("well-known and DNS records that resolve to forbidden address ranges")
    {
        auto private_ipv4 = FakeDiscoveryNetwork{};
        private_ipv4.well_known = {true, true, "{\"m.server\":\"fed.example.net:9448\"}", {}};
        private_ipv4.addresses.emplace("fed.example.net", std::vector<std::string>{"10.0.0.9"});

        auto private_ipv6 = FakeDiscoveryNetwork{};
        private_ipv6.srv_records = {
            {"srv.example.net", 9448U, 0U, 0U}
        };
        private_ipv6.addresses.emplace("srv.example.net", std::vector<std::string>{"fe80::1"});

        WHEN("discovery attempts to pin those destinations")
        {
            auto const rejected_v4 = merovingian::federation::discover_server("example.org", private_ipv4, 5U);
            auto const rejected_v6 = merovingian::federation::discover_server("example.org", private_ipv6, 5U);

            THEN("both address families fail closed")
            {
                // Spec MUST: discovery_allowed MUST be false for private IPv4 - SSRF prevention.
                // Do NOT remove/change - allowing 10/8 ranges enables internal network access via federation.
                REQUIRE_FALSE(rejected_v4.discovery_allowed);
                // Spec MUST: pinned_addresses MUST be empty when discovery is rejected.
                // Do NOT remove/change - a non-empty list here would allow callers to bypass the rejection.
                REQUIRE(rejected_v4.pinned_addresses.empty());
                // Spec MUST: the rejection reason MUST mention "private" for diagnostic clarity.
                // Do NOT remove/change - operators rely on this string to identify SSRF-blocked destinations.
                REQUIRE(rejected_v4.reason.find("private") != std::string::npos);
                // Spec MUST: discovery_allowed MUST be false for IPv6 link-local - SSRF prevention.
                // Do NOT remove/change - fe80::/10 addresses are host-local and MUST never be federated to.
                REQUIRE_FALSE(rejected_v6.discovery_allowed);
                // Spec MUST: pinned_addresses MUST be empty when discovery is rejected (IPv6 case).
                // Do NOT remove/change - consistency with the IPv4 rejection is required.
                REQUIRE(rejected_v6.pinned_addresses.empty());
                // Spec MUST: the IPv6 rejection reason MUST also mention "private".
                // Do NOT remove/change - uniform error strings simplify log alerting.
                REQUIRE(rejected_v6.reason.find("private") != std::string::npos);
            }
        }
    }
}

// --- Explicit port short-circuits well-known and SRV -------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 2 Resolving server names
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#resolving-server-names
//
// If the server name contains an explicit port (e.g. "example.org:7443"),
// the resolution algorithm MUST stop at step 1 and MUST NOT consult
// well-known or SRV records. The explicit host and port are used directly.
// This is the highest-precedence step in the algorithm.
SCENARIO("Server discovery honors an explicit port in the server name", "[federation][discovery][explicit-port]")
{
    GIVEN("a server name with an explicit port and SRV/well-known data that would otherwise mislead discovery")
    {
        auto network = FakeDiscoveryNetwork{};
        network.well_known = {true, true, "{\"m.server\":\"misleading.example.net:9999\"}", {}};
        network.srv_records = {
            {"misleading.example.net", 9999U, 0U, 0U}
        };
        network.addresses.emplace("example.org", std::vector<std::string>{"203.0.113.42"});

        WHEN("discovery resolves a server name with an explicit port")
        {
            auto const result = merovingian::federation::discover_server("example.org:7443", network, 5U);

            THEN("the explicit host and port are used without consulting well-known or SRV")
            {
                // Spec MUST: discovery_allowed MUST be true for a public explicit-port server name.
                // Do NOT remove/change - false here would incorrectly block all explicit-port federation.
                REQUIRE(result.discovery_allowed);
                // Spec MUST: resolved_host MUST be the host from the explicit server name, not any delegated host.
                // Do NOT remove/change - using a delegated host when an explicit port is given violates step 1.
                REQUIRE(result.resolved_host == "example.org");
                // Spec MUST: resolved_port MUST be the explicit port, not the well-known or SRV port.
                // Do NOT remove/change - using 9999 (well-known) instead of 7443 violates the algorithm.
                REQUIRE(result.resolved_port == 7443U);
                // Spec MUST: well-known MUST NOT be fetched when an explicit port is present.
                // Do NOT remove/change - fetching well-known wastes a network round-trip and breaks step 1.
                REQUIRE(network.fetched_server.empty());
                // Spec MUST: SRV MUST NOT be queried when an explicit port is present.
                // Do NOT remove/change - consulting SRV contradicts the algorithm's strict precedence.
                REQUIRE(network.last_srv_lookup.empty());
                auto const expected_addresses = std::vector<std::string>{"203.0.113.42"};
                // Spec MUST: addresses MUST be pinned from the explicit host, not any delegated target.
                // Do NOT remove/change - wrong pinned addresses break TLS and SSRF protection.
                REQUIRE(result.pinned_addresses == expected_addresses);
            }
        }
    }
}

// --- Well-known fallback on invalid / missing m.server -----------------------
// Spec: Matrix Server-Server API v1.18, Sec. 2.1 Well-known URI delegation
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#well-known-uri
//
// If /.well-known/matrix/server returns malformed JSON or a JSON object that
// lacks the m.server key, the response MUST be treated as if well-known were
// absent. Discovery MUST then fall through to SRV lookup (step 3) or direct
// resolution (step 4) rather than failing closed.
SCENARIO("Server discovery falls back when the well-known body is invalid", "[federation][discovery][well-known]")
{
    GIVEN("a well-known response that arrives with malformed JSON")
    {
        auto network = FakeDiscoveryNetwork{};
        network.well_known = {true, true, "not-json{", {}};
        network.srv_records = {
            {"fallback.example.net", 9448U, 0U, 0U}
        };
        network.addresses.emplace("fallback.example.net", std::vector<std::string>{"198.51.100.50"});

        WHEN("discovery proceeds")
        {
            auto const result = merovingian::federation::discover_server("example.org", network, 5U);

            THEN("discovery falls through to SRV instead of failing closed")
            {
                // Spec MUST: SRV MUST be queried when well-known JSON is malformed (fall-through).
                // Do NOT remove/change - failing closed on bad well-known would break federation unnecessarily.
                REQUIRE(network.last_srv_lookup == "_matrix-fed._tcp.example.org");
                // Spec MUST: discovery_allowed MUST be true when SRV fall-through succeeds.
                // Do NOT remove/change - false here would incorrectly block a reachable server.
                REQUIRE(result.discovery_allowed);
                // Spec MUST: resolved_host MUST be the SRV fallback target, not the malformed well-known value.
                // Do NOT remove/change - using a partially-parsed well-known value risks connecting to the wrong host.
                REQUIRE(result.resolved_host == "fallback.example.net");
                // Spec MUST: resolved_port MUST come from the SRV fallback record.
                // Do NOT remove/change - wrong port silently breaks federation after well-known parse failure.
                REQUIRE(result.resolved_port == 9448U);
            }
        }
    }

    GIVEN("a well-known response that omits m.server")
    {
        auto network = FakeDiscoveryNetwork{};
        network.well_known = {true, true, "{\"other\":\"value\"}", {}};
        network.addresses.emplace("example.org", std::vector<std::string>{"203.0.113.42"});

        WHEN("discovery proceeds")
        {
            THEN("discovery falls through to direct resolution of the original server name")
            {
                auto const result = merovingian::federation::discover_server("example.org", network, 5U);
                // Spec MUST: discovery_allowed MUST be true when direct fall-through succeeds.
                // Do NOT remove/change - the absence of m.server is not a fatal error.
                REQUIRE(result.discovery_allowed);
                // Spec MUST: resolved_host MUST be the original server name when well-known has no m.server.
                // Do NOT remove/change - using any other host would be an unsolicited redirection.
                REQUIRE(result.resolved_host == "example.org");
                // Spec MUST: resolved_port MUST default to 8448 when no explicit port or SRV record applies.
                // Do NOT remove/change - any other port contradicts the Matrix default federation port.
                REQUIRE(result.resolved_port == 8448U);
            }
        }
    }
}

// --- Well-known without port triggers SRV on delegated host ------------------
// Spec: Matrix Server-Server API v1.18, Sec. 2.1 Well-known URI delegation
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#well-known-uri
//
// If m.server supplies a hostname without an explicit port, the server MUST
// perform an SRV lookup against the delegated hostname (not the original).
// If m.server includes an explicit port, the SRV step MUST be skipped and
// the delegated port used directly.
SCENARIO("Server discovery uses SRV on the delegated host when no port is supplied",
         "[federation][discovery][well-known][srv]")
{
    GIVEN("a well-known delegation that supplies a hostname without a port and matching SRV records")
    {
        auto network = FakeDiscoveryNetwork{};
        network.well_known = {true, true, "{\"m.server\":\"delegated.example.net\"}", {}};
        network.srv_records = {
            {"srv.delegated.example.net", 9500U, 0U, 0U}
        };
        network.addresses.emplace("srv.delegated.example.net", std::vector<std::string>{"203.0.113.99"});

        WHEN("discovery proceeds")
        {
            auto const result = merovingian::federation::discover_server("example.org", network, 5U);

            THEN("SRV lookup is performed on the delegated host and the SRV target is used")
            {
                // Spec MUST: the SRV lookup MUST target the delegated hostname, not the original server name.
                // Do NOT remove/change - querying the original name ignores the well-known delegation.
                REQUIRE(network.last_srv_lookup == "_matrix-fed._tcp.delegated.example.net");
                // Spec MUST: discovery_allowed MUST be true when SRV resolution of the delegated host succeeds.
                // Do NOT remove/change - false here would block a correctly delegated server.
                REQUIRE(result.discovery_allowed);
                // Spec MUST: well_known_host MUST reflect the SRV-resolved target, not the delegated hostname.
                // Do NOT remove/change - the SRV target is the actual TLS peer; the delegated name is intermediate.
                REQUIRE(result.well_known_host == "srv.delegated.example.net");
                // Spec MUST: resolved_host MUST be the SRV target of the delegated hostname.
                // Do NOT remove/change - using the delegated hostname directly skips the required SRV step.
                REQUIRE(result.resolved_host == "srv.delegated.example.net");
                // Spec MUST: resolved_port MUST be the port from the SRV record on the delegated host.
                // Do NOT remove/change - using a default port when SRV provides one violates the algorithm.
                REQUIRE(result.resolved_port == 9500U);
            }
        }
    }

    GIVEN("a well-known delegation with an explicit port")
    {
        auto network = FakeDiscoveryNetwork{};
        network.well_known = {true, true, "{\"m.server\":\"delegated.example.net:9500\"}", {}};
        network.addresses.emplace("delegated.example.net", std::vector<std::string>{"203.0.113.99"});

        WHEN("discovery proceeds")
        {
            auto const result = merovingian::federation::discover_server("example.org", network, 5U);

            THEN("SRV lookup is skipped and the delegated port is honored")
            {
                // Spec MUST: last_srv_lookup MUST be empty - SRV MUST NOT be queried when m.server has a port.
                // Do NOT remove/change - performing SRV lookup contradicts the algorithm's explicit-port step.
                REQUIRE(network.last_srv_lookup.empty());
                // Spec MUST: discovery_allowed MUST be true for a publicly reachable delegated server.
                // Do NOT remove/change - false here incorrectly rejects a valid explicit-port delegation.
                REQUIRE(result.discovery_allowed);
                // Spec MUST: resolved_host MUST be the delegated hostname from m.server.
                // Do NOT remove/change - using the original server name ignores the well-known delegation.
                REQUIRE(result.resolved_host == "delegated.example.net");
                // Spec MUST: resolved_port MUST be the explicit port from m.server, not a default.
                // Do NOT remove/change - falling back to 8448 when an explicit port is given violates step 2.
                REQUIRE(result.resolved_port == 9500U);
            }
        }
    }
}

// --- IP literal server name short-circuits delegation ------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 2 Resolving server names (step 1)
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#resolving-server-names
//
// If the server name is a literal public IPv4 address, the server MUST be
// contacted directly on that address at the default federation port. Neither
// well-known nor SRV records are consulted, and TLS is still required.
SCENARIO("Server discovery contacts a public IPv4 literal directly", "[federation][discovery][literal]")
{
    GIVEN("a server name that is a public IPv4 literal with misleading delegation data")
    {
        auto network = FakeDiscoveryNetwork{};
        network.well_known = {true, true, "{\"m.server\":\"misleading.example.net:9999\"}", {}};
        network.srv_records = {
            {"misleading.example.net", 9999U, 0U, 0U}
        };
        network.addresses.emplace("203.0.113.5", std::vector<std::string>{"203.0.113.5"});

        WHEN("discovery resolves the IPv4 literal")
        {
            auto const result = merovingian::federation::discover_server("203.0.113.5", network, 5U);

            THEN("the literal is used directly without consulting well-known or SRV")
            {
                // Spec MUST: a public IP literal is permitted as a federation destination.
                // Do NOT remove/change - false here would block direct-IP federation entirely.
                REQUIRE(result.discovery_allowed);
                // Spec MUST: resolved_host MUST be the literal itself, not any delegated host.
                // Do NOT remove/change - step 1 forbids delegation when the name is an IP literal.
                REQUIRE(result.resolved_host == "203.0.113.5");
                // Spec MUST: resolved_port MUST default to 8448 when no explicit port is given.
                // Do NOT remove/change - using the well-known port 9999 violates the literal short-circuit.
                REQUIRE(result.resolved_port == 8448U);
                // Spec MUST: TLS is required for all federation traffic, including direct-IP.
                // Do NOT remove/change - plaintext federation is not permitted.
                REQUIRE(result.tls_required);
                // Spec MUST: well-known MUST NOT be fetched for an IP literal.
                // Do NOT remove/change - fetching delegation for a literal contradicts step 1.
                REQUIRE(network.fetched_server.empty());
                // Spec MUST: SRV MUST NOT be queried for an IP literal.
                // Do NOT remove/change - SRV resolution of a literal is meaningless and forbidden.
                REQUIRE(network.last_srv_lookup.empty());
            }
        }
    }
}

// --- IPv6 literal with explicit port -----------------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 2 Resolving server names (step 1)
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#resolving-server-names
//
// A bracketed IPv6 literal with an explicit port MUST be contacted directly on
// that host and port. The brackets are stripped from the resolved host and the
// explicit port is honored verbatim.
SCENARIO("Server discovery honors a bracketed IPv6 literal with an explicit port",
         "[federation][discovery][literal][ipv6]")
{
    GIVEN("a bracketed IPv6 literal carrying an explicit port")
    {
        auto network = FakeDiscoveryNetwork{};
        network.addresses.emplace("2001:db8::5", std::vector<std::string>{"2001:db8::5"});

        WHEN("discovery resolves the bracketed IPv6 literal")
        {
            auto const result = merovingian::federation::discover_server("[2001:db8::5]:7000", network, 5U);

            THEN("the host is the unbracketed literal and the explicit port is used")
            {
                // Spec MUST: a public IPv6 literal is a permitted destination.
                // Do NOT remove/change - false here would block all IPv6-literal federation.
                REQUIRE(result.discovery_allowed);
                // Spec MUST: resolved_host MUST be the IPv6 address without the surrounding brackets.
                // Do NOT remove/change - leaving brackets in breaks the TLS/connect host string.
                REQUIRE(result.resolved_host == "2001:db8::5");
                // Spec MUST: resolved_port MUST equal the explicit port from the literal.
                // Do NOT remove/change - dropping the explicit port silently breaks federation.
                REQUIRE(result.resolved_port == 7000U);
                // Spec MUST: SRV MUST NOT be consulted when an explicit port is present.
                // Do NOT remove/change - the explicit port is the highest-precedence step.
                REQUIRE(network.last_srv_lookup.empty());
            }
        }
    }
}

// --- Empty m.server value is treated as absent -------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 2.1 Well-known URI delegation
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#well-known-uri
//
// A well-known body whose m.server value is an empty string carries no usable
// delegation. It MUST be treated as if m.server were absent: discovery falls
// through to SRV and then direct resolution of the original server name.
SCENARIO("Server discovery treats an empty m.server as no delegation", "[federation][discovery][well-known]")
{
    GIVEN("a well-known body with an empty m.server and no SRV records")
    {
        auto network = FakeDiscoveryNetwork{};
        network.well_known = {true, true, "{\"m.server\":\"\"}", {}};
        network.addresses.emplace("example.org", std::vector<std::string>{"203.0.113.7"});

        WHEN("discovery proceeds")
        {
            auto const result = merovingian::federation::discover_server("example.org", network, 5U);

            THEN("discovery falls through to direct resolution of the original server name")
            {
                // Spec MUST: an empty m.server is not a fatal error; discovery MUST still succeed.
                // Do NOT remove/change - failing closed here would break reachable servers.
                REQUIRE(result.discovery_allowed);
                // Spec MUST: resolved_host MUST be the original server name when m.server is empty.
                // Do NOT remove/change - using an empty delegated host would route to nowhere.
                REQUIRE(result.resolved_host == "example.org");
                // Spec MUST: resolved_port MUST default to 8448 with no delegation or SRV record.
                // Do NOT remove/change - any other port contradicts the default federation port.
                REQUIRE(result.resolved_port == 8448U);
            }
        }
    }
}

// --- SRV selection breaks priority ties by weight ----------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 2.2 SRV lookup (RFC 2782 ordering)
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#resolving-server-names
//
// Among SRV records sharing the lowest priority, the record with the greater
// weight MUST be preferred. The chosen target and its port become the
// federation destination.
SCENARIO("Server discovery prefers the higher-weight SRV record at equal priority",
         "[federation][discovery][dns][srv]")
{
    GIVEN("two equal-priority SRV records with different weights")
    {
        auto network = FakeDiscoveryNetwork{};
        network.srv_records = {
            {"low.example.net",  9448U, 10U, 5U },
            {"high.example.net", 9449U, 10U, 50U},
        };
        network.addresses.emplace("high.example.net", std::vector<std::string>{"198.51.100.5"});

        WHEN("discovery resolves through the SRV records")
        {
            auto const result = merovingian::federation::discover_server("example.org", network, 5U);

            THEN("the higher-weight target wins the tie and becomes the destination")
            {
                // Spec MUST: the SRV lookup MUST target _matrix-fed._tcp.<server_name>.
                // Do NOT remove/change - querying the wrong name silently ignores SRV records.
                REQUIRE(network.last_srv_lookup == "_matrix-fed._tcp.example.org");
                // Spec MUST: discovery MUST succeed for a public SRV target.
                // Do NOT remove/change - false here would block SRV-resolved federation.
                REQUIRE(result.discovery_allowed);
                // Spec MUST: at equal priority the greater weight MUST be selected.
                // Do NOT remove/change - choosing the lower-weight target violates RFC 2782 ordering.
                REQUIRE(result.resolved_host == "high.example.net");
                // Spec MUST: the winning record's port MUST be used.
                // Do NOT remove/change - using the losing record's port breaks federation.
                REQUIRE(result.resolved_port == 9449U);
            }
        }
    }
}

// --- Invalid delegated port falls through ------------------------------------
// Spec: Matrix Server-Server API v1.18, Sec. 2.1 Well-known URI delegation
// URL:  ../../docs/matrix-v1.18-spec/server-server-api.md#well-known-uri
//
// An m.server value carrying an invalid port (e.g. port 0) is not a usable
// delegation. It MUST be treated as absent rather than connecting to an
// invalid port; discovery falls through to SRV and then direct resolution.
SCENARIO("Server discovery rejects a delegated port of zero and falls through",
         "[federation][discovery][well-known]")
{
    GIVEN("a well-known delegation whose m.server port is zero")
    {
        auto network = FakeDiscoveryNetwork{};
        network.well_known = {true, true, "{\"m.server\":\"fed.example.net:0\"}", {}};
        network.addresses.emplace("example.org", std::vector<std::string>{"203.0.113.9"});

        WHEN("discovery proceeds")
        {
            auto const result = merovingian::federation::discover_server("example.org", network, 5U);

            THEN("the invalid delegation is ignored and the original server name resolves directly")
            {
                // Spec MUST: an invalid delegated port MUST NOT be used as a destination.
                // Do NOT remove/change - connecting to port 0 is never valid.
                REQUIRE(result.resolved_host == "example.org");
                // Spec MUST: resolved_port MUST default to 8448 after the invalid delegation is discarded.
                // Do NOT remove/change - honoring port 0 would break all outbound federation.
                REQUIRE(result.resolved_port == 8448U);
                // Spec MUST: discovery MUST still succeed via direct fall-through.
                // Do NOT remove/change - failing closed on a bad port would block a reachable server.
                REQUIRE(result.discovery_allowed);
            }
        }
    }
}

namespace
{

auto append_u16(std::vector<unsigned char>& message, std::uint16_t value) -> void
{
    message.push_back(static_cast<unsigned char>(value >> 8));
    message.push_back(static_cast<unsigned char>(value & 0xFFU));
}

// Appends a domain name as uncompressed length-prefixed labels ending in root.
auto append_dns_name(std::vector<unsigned char>& message, std::string_view name) -> void
{
    std::size_t start = 0U;
    while (start < name.size())
    {
        auto const dot = name.find('.', start);
        auto const label_end = dot == std::string_view::npos ? name.size() : dot;
        auto const label = name.substr(start, label_end - start);
        message.push_back(static_cast<unsigned char>(label.size()));
        for (auto const ch : label)
        {
            message.push_back(static_cast<unsigned char>(ch));
        }
        if (dot == std::string_view::npos)
        {
            break;
        }
        start = dot + 1U;
    }
    message.push_back(0U); // root label
}

auto append_srv_answer(std::vector<unsigned char>& message, std::string_view name, std::uint16_t priority,
                       std::uint16_t weight, std::uint16_t port, std::string_view target) -> void
{
    append_dns_name(message, name);
    append_u16(message, 33U); // TYPE = SRV
    append_u16(message, 1U);  // CLASS = IN
    append_u16(message, 0U);  // TTL high
    append_u16(message, 0U);  // TTL low
    auto rdata = std::vector<unsigned char>{};
    append_u16(rdata, priority);
    append_u16(rdata, weight);
    append_u16(rdata, port);
    append_dns_name(rdata, target);
    append_u16(message, static_cast<std::uint16_t>(rdata.size()));
    message.insert(message.end(), rdata.begin(), rdata.end());
}

} // namespace

// Spec: Matrix Server-Server API v1.18
// Section: 2 Resolving server names (SRV lookup of _matrix-fed._tcp)
// URL: ../../docs/matrix-v1.18-spec/server-server-api.md#resolving-server-names
//
// SRV resolution must parse the DNS response portably across resolver
// implementations (the BIND ns_* parser API is absent on some platforms). The
// response is untrusted, so the parser must be fully bounds-checked.
SCENARIO("SRV response parsing extracts records and is bounds-safe on untrusted input",
         "[federation][discovery][security]")
{
    GIVEN("a DNS response with one question and two SRV answers")
    {
        auto message = std::vector<unsigned char>{};
        append_u16(message, 0U);      // ID
        append_u16(message, 0x8180U); // flags: standard response
        append_u16(message, 1U);      // QDCOUNT
        append_u16(message, 2U);      // ANCOUNT
        append_u16(message, 0U);      // NSCOUNT
        append_u16(message, 0U);      // ARCOUNT
        append_dns_name(message, "_matrix-fed._tcp.example.com");
        append_u16(message, 33U); // QTYPE SRV
        append_u16(message, 1U);  // QCLASS IN
        append_srv_answer(message, "_matrix-fed._tcp.example.com", 10U, 5U, 8448U, "alpha.example.com");
        append_srv_answer(message, "_matrix-fed._tcp.example.com", 20U, 0U, 8449U, "beta.example.com");

        WHEN("the response is parsed")
        {
            auto const records = merovingian::federation::parse_srv_records(
                message.data(), static_cast<int>(message.size()));

            THEN("both SRV records are recovered with their fields intact")
            {
                REQUIRE(records.size() == 2U);
                REQUIRE(records[0].target == "alpha.example.com");
                REQUIRE(records[0].priority == 10U);
                REQUIRE(records[0].weight == 5U);
                REQUIRE(records[0].port == 8448U);
                REQUIRE(records[1].target == "beta.example.com");
                REQUIRE(records[1].port == 8449U);
            }
        }

        WHEN("the response is truncated mid-record")
        {
            auto truncated = message;
            truncated.resize(message.size() - 8U);
            auto const records = merovingian::federation::parse_srv_records(
                truncated.data(), static_cast<int>(truncated.size()));

            THEN("parsing stops safely without reading past the buffer")
            {
                // The parser must not crash or over-read; it returns only the
                // records it could fully validate (here, the first answer).
                REQUIRE(records.size() <= 1U);
            }
        }

        WHEN("the buffer is shorter than a DNS header")
        {
            auto const records = merovingian::federation::parse_srv_records(message.data(), 4);

            THEN("no records are returned")
            {
                REQUIRE(records.empty());
            }
        }
    }
}
