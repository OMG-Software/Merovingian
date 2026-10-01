// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/events/event.hpp"
#include "merovingian/federation/cached_server_discovery.hpp"
#include "merovingian/federation/security.hpp"
#include "merovingian/federation/server_discovery.hpp"

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>

SCENARIO("Federation discovery accepts public TLS remotes and rejects SSRF targets",
         "[federation][security][discovery]")
{
    GIVEN("public and private remote discovery records")
    {
        auto public_remote = merovingian::federation::RemoteServerRecord{};
        public_remote.server_name = "matrix.example.org";
        public_remote.well_known_host = "matrix.example.org";
        public_remote.resolved_host = "matrix.example.org";
        public_remote.resolved_addresses = {"203.0.113.10"};
        public_remote.tls_required = true;

        auto private_remote = public_remote;
        private_remote.resolved_addresses = {"127.0.0.1"};

        WHEN("discovery policy is evaluated")
        {
            auto const accepted = merovingian::federation::federation_discovery_policy(public_remote);
            auto const rejected = merovingian::federation::federation_discovery_policy(private_remote);

            THEN("public remotes pass and private or loopback remotes fail closed")
            {
                REQUIRE(accepted.accepted);
                REQUIRE_FALSE(rejected.accepted);
                REQUIRE(rejected.reason == "remote address is private or loopback");
            }
        }
    }
}

SCENARIO("ip_address_is_private_or_loopback classifies RFC1918, 172.16/12, loopback, ULA, and link-local exactly",
         "[federation][security][ssrf]")
{
    GIVEN("a range of IPv4 and IPv6 address literals")
    {
        WHEN("each address is classified by the inet_pton-based helper")
        {
            // IPv4 private / loopback / link-local that must be blocked.
            THEN("private and loopback IPv4 addresses are private or loopback")
            {
                REQUIRE(merovingian::federation::ip_address_is_private_or_loopback("127.0.0.1"));
                REQUIRE(merovingian::federation::ip_address_is_private_or_loopback("10.0.0.1"));
                REQUIRE(merovingian::federation::ip_address_is_private_or_loopback("192.168.1.1"));
                REQUIRE(merovingian::federation::ip_address_is_private_or_loopback("169.254.1.1"));
                REQUIRE(merovingian::federation::ip_address_is_private_or_loopback("172.16.0.1"));
                REQUIRE(merovingian::federation::ip_address_is_private_or_loopback("172.31.255.255"));
                REQUIRE(merovingian::federation::ip_address_is_private_or_loopback("0.0.0.0"));
            }
            THEN("public IPv4 addresses outside the private ranges are not private or loopback")
            {
                REQUIRE_FALSE(merovingian::federation::ip_address_is_private_or_loopback("8.8.8.8"));
                REQUIRE_FALSE(merovingian::federation::ip_address_is_private_or_loopback("172.1.0.1"));
                REQUIRE_FALSE(merovingian::federation::ip_address_is_private_or_loopback("172.10.0.1"));
                REQUIRE_FALSE(merovingian::federation::ip_address_is_private_or_loopback("172.32.0.1"));
                REQUIRE_FALSE(merovingian::federation::ip_address_is_private_or_loopback("203.0.113.10"));
            }
            THEN("IPv6 loopback, ULA, link-local, and IPv4-mapped private addresses are private or loopback")
            {
                REQUIRE(merovingian::federation::ip_address_is_private_or_loopback("::1"));
                REQUIRE(merovingian::federation::ip_address_is_private_or_loopback("fc00::1"));
                REQUIRE(merovingian::federation::ip_address_is_private_or_loopback("fd00::1"));
                REQUIRE(merovingian::federation::ip_address_is_private_or_loopback("fe80::1"));
                REQUIRE(merovingian::federation::ip_address_is_private_or_loopback("::ffff:127.0.0.1"));
                REQUIRE(merovingian::federation::ip_address_is_private_or_loopback("::ffff:172.16.0.1"));
            }
            THEN("public IPv6 addresses are not private or loopback")
            {
                REQUIRE_FALSE(merovingian::federation::ip_address_is_private_or_loopback("2001:4860:4860::8888"));
                REQUIRE_FALSE(merovingian::federation::ip_address_is_private_or_loopback("::ffff:8.8.8.8"));
            }
            THEN("the localhost hostname is treated as private or loopback (fail-safe)")
            {
                REQUIRE(merovingian::federation::ip_address_is_private_or_loopback("localhost"));
            }
        }
    }
}

SCENARIO("Federation discovery rejects DNS rebinding host drift", "[federation][security][discovery]")
{
    GIVEN("a remote whose well-known host differs from the resolved host")
    {
        auto remote = merovingian::federation::RemoteServerRecord{};
        remote.server_name = "matrix.example.org";
        remote.well_known_host = "matrix.example.org";
        remote.resolved_host = "evil.example.org";
        remote.resolved_addresses = {"203.0.113.10"};
        remote.tls_required = true;

        WHEN("discovery policy is evaluated")
        {
            auto const decision = merovingian::federation::federation_discovery_policy(remote);

            THEN("host drift is rejected")
            {
                REQUIRE_FALSE(decision.accepted);
                REQUIRE(decision.reason == "well-known host and resolved host mismatch");
            }
        }
    }
}

SCENARIO("Federation request and event signature hooks fail closed", "[federation][security][signatures]")
{
    GIVEN("request and event signatures")
    {
        auto valid_request = merovingian::federation::FederationRequestSignature{
            "matrix.example.org",
            "ed25519:auto",
            "signature-bytes",
            true,
        };
        auto invalid_request = valid_request;
        invalid_request.canonical_json_verified = false;
        auto event_signatures = std::vector<merovingian::events::EventSignature>{
            {"matrix.example.org", "ed25519:auto", "signature-bytes"},
        };

        WHEN("signature hooks are evaluated")
        {
            auto const valid_request_decision =
                merovingian::federation::verify_federation_request_signature(valid_request);
            auto const invalid_request_decision =
                merovingian::federation::verify_federation_request_signature(invalid_request);
            auto const valid_event_decision =
                merovingian::federation::verify_federation_event_signatures(event_signatures, "matrix.example.org");
            auto const invalid_event_decision =
                merovingian::federation::verify_federation_event_signatures(event_signatures, "elsewhere.example.org");

            THEN("only verified request and expected-server event signatures are accepted")
            {
                REQUIRE(valid_request_decision.accepted);
                REQUIRE_FALSE(invalid_request_decision.accepted);
                REQUIRE(invalid_request_decision.reason == "canonical JSON signature verification required");
                REQUIRE(valid_event_decision.accepted);
                REQUIRE_FALSE(invalid_event_decision.accepted);
                REQUIRE(invalid_event_decision.reason == "missing event signature for expected server");
            }
        }
    }
}

SCENARIO("Remote trust controls cover rate limit, backoff, circuit breaker, reputation, and quarantine",
         "[federation][security][trust]")
{
    GIVEN("remote trust states")
    {
        auto healthy = merovingian::federation::RemoteTrustState{};
        healthy.reputation_score = 100;
        auto backoff = healthy;
        backoff.consecutive_failures = 3;
        auto circuit_open = healthy;
        circuit_open.circuit_open = true;
        auto low_reputation = healthy;
        low_reputation.reputation_score = 24;
        auto quarantined = healthy;
        quarantined.quarantined = true;

        WHEN("trust policy is evaluated")
        {
            auto const rate_limit = merovingian::federation::federation_remote_rate_limit();
            auto const healthy_decision = merovingian::federation::remote_trust_policy(healthy);
            auto const backoff_decision = merovingian::federation::remote_trust_policy(backoff);
            auto const circuit_decision = merovingian::federation::remote_trust_policy(circuit_open);
            auto const reputation_decision = merovingian::federation::remote_trust_policy(low_reputation);
            auto const quarantine_decision = merovingian::federation::remote_trust_policy(quarantined);

            THEN("only healthy remotes are accepted")
            {
                REQUIRE(rate_limit.max_requests == 120U);
                REQUIRE(rate_limit.window_seconds == 60U);
                REQUIRE(healthy_decision.accepted);
                REQUIRE_FALSE(backoff_decision.accepted);
                REQUIRE(backoff_decision.apply_backoff);
                REQUIRE_FALSE(circuit_decision.accepted);
                REQUIRE(circuit_decision.reason == "remote circuit breaker is open");
                REQUIRE_FALSE(reputation_decision.accepted);
                REQUIRE(reputation_decision.reason == "remote reputation is too low");
                REQUIRE_FALSE(quarantine_decision.accepted);
                REQUIRE(quarantine_decision.reason == "remote server is quarantined");
            }
        }
    }
}

SCENARIO("Remote backoff decays after a quiet period and a fresh failure restarts the count",
         "[federation][security][trust][fed4]")
{
    GIVEN("a remote whose consecutive-failure backoff was tripped at a known time")
    {
        auto const tripped_at = std::chrono::steady_clock::time_point{std::chrono::hours{100}};
        auto state = merovingian::federation::RemoteTrustState{};
        state.consecutive_failures = 3U;
        state.last_failure_at = tripped_at;
        auto const window = merovingian::federation::remote_backoff_decay_window;

        WHEN("the policy is evaluated before, exactly at, and after the decay window")
        {
            auto const before = merovingian::federation::remote_trust_policy(state, tripped_at + window / 2);
            auto const at_edge = merovingian::federation::remote_trust_policy(state, tripped_at + window);
            auto const after =
                merovingian::federation::remote_trust_policy(state, tripped_at + window + std::chrono::seconds{1});

            THEN("the backoff holds until the window has elapsed and is then lifted")
            {
                REQUIRE(window == std::chrono::minutes{5});
                REQUIRE_FALSE(before.accepted);
                REQUIRE(before.apply_backoff);
                REQUIRE(at_edge.accepted);
                REQUIRE(after.accepted);
            }
        }

        WHEN("a failure is recorded after the quiet period")
        {
            auto const later = tripped_at + window + std::chrono::seconds{1};
            merovingian::federation::record_remote_trust_failure(state, later);

            THEN("the stale count is discarded and the failure counts as the first")
            {
                REQUIRE(state.consecutive_failures == 1U);
                REQUIRE(state.last_failure_at == later);
            }
        }

        WHEN("failures are recorded inside the window")
        {
            merovingian::federation::record_remote_trust_failure(state, tripped_at + std::chrono::seconds{10});

            THEN("the count keeps rising and the window restarts from the newest failure")
            {
                REQUIRE(state.consecutive_failures == 4U);
                REQUIRE(state.last_failure_at == tripped_at + std::chrono::seconds{10});
            }
        }

        WHEN("quarantine or a tripped circuit is set, however old the last failure is")
        {
            auto quarantined = state;
            quarantined.quarantined = true;
            auto open_circuit = state;
            open_circuit.circuit_open = true;
            auto const much_later = tripped_at + window * 100;

            THEN("time never lifts them")
            {
                REQUIRE_FALSE(merovingian::federation::remote_trust_policy(quarantined, much_later).accepted);
                REQUIRE_FALSE(merovingian::federation::remote_trust_policy(open_circuit, much_later).accepted);
            }
        }
    }
}

SCENARIO("address_set_allowed rejects private, loopback, CGNAT, multicast, NAT64, and reserved ranges",
         "[federation][security][ssrf]")
{
    GIVEN("address sets containing public and disallowed addresses")
    {
        WHEN("the set is evaluated")
        {
            THEN("an empty set is disallowed")
            {
                REQUIRE_FALSE(merovingian::federation::address_set_allowed({}));
            }
            THEN("a public address set is allowed")
            {
                REQUIRE(merovingian::federation::address_set_allowed({"203.0.113.10"}));
                REQUIRE(merovingian::federation::address_set_allowed({"8.8.8.8", "2001:4860:4860::8888"}));
            }
            THEN("loopback and RFC1918 are rejected")
            {
                REQUIRE_FALSE(merovingian::federation::address_set_allowed({"127.0.0.1"}));
                REQUIRE_FALSE(merovingian::federation::address_set_allowed({"10.0.0.1"}));
                REQUIRE_FALSE(merovingian::federation::address_set_allowed({"172.16.0.1"}));
                REQUIRE_FALSE(merovingian::federation::address_set_allowed({"192.168.1.1"}));
            }
            THEN("link-local and CGNAT are rejected")
            {
                REQUIRE_FALSE(merovingian::federation::address_set_allowed({"169.254.1.1"}));
                REQUIRE_FALSE(merovingian::federation::address_set_allowed({"100.64.0.1"}));
                REQUIRE_FALSE(merovingian::federation::address_set_allowed({"100.126.255.255"}));
            }
            THEN("multicast and reserved space are rejected")
            {
                REQUIRE_FALSE(merovingian::federation::address_set_allowed({"224.0.0.1"}));
                REQUIRE_FALSE(merovingian::federation::address_set_allowed({"240.0.0.1"}));
                REQUIRE_FALSE(merovingian::federation::address_set_allowed({"255.255.255.255"}));
            }
            THEN("IPv6 non-public ranges are rejected")
            {
                REQUIRE_FALSE(merovingian::federation::address_set_allowed({"::1"}));
                REQUIRE_FALSE(merovingian::federation::address_set_allowed({"fc00::1"}));
                REQUIRE_FALSE(merovingian::federation::address_set_allowed({"fe80::1"}));
                REQUIRE_FALSE(merovingian::federation::address_set_allowed({"64:ff9b::1"}));
                REQUIRE_FALSE(merovingian::federation::address_set_allowed({"ff02::1"}));
            }
            THEN("IPv4-mapped private addresses are rejected")
            {
                REQUIRE_FALSE(merovingian::federation::address_set_allowed({"::ffff:127.0.0.1"}));
                REQUIRE_FALSE(merovingian::federation::address_set_allowed({"::ffff:10.0.0.1"}));
            }
            THEN("a single disallowed address taints the whole set")
            {
                REQUIRE_FALSE(merovingian::federation::address_set_allowed({"203.0.113.10", "127.0.0.1"}));
            }
        }
    }
}

namespace
{

struct FilteringDiscoveryNetwork final : public merovingian::federation::ServerDiscoveryNetwork
{
    std::string next_address{"203.0.113.1"};

    [[nodiscard]] auto fetch_well_known(std::string_view, std::uint32_t)
        -> merovingian::federation::WellKnownServerResult override
    {
        return {};
    }

    [[nodiscard]] auto lookup_srv(std::string_view) -> std::vector<merovingian::federation::SrvRecord> override
    {
        return {};
    }

    [[nodiscard]] auto lookup_addresses(std::string_view, std::uint16_t)
        -> merovingian::federation::ResolvedAddressSet override
    {
        return {true, {next_address}, {}};
    }
};

} // namespace

SCENARIO("CachedServerDiscovery::lookup_addresses_filtered rejects attacker-influenced private destinations",
         "[federation][security][ssrf][discovery]")
{
    GIVEN("a cached discovery wrapping a network that returns a public address")
    {
        auto network = FilteringDiscoveryNetwork{};
        auto discovery = merovingian::federation::CachedServerDiscovery{network, 60000U, []() -> std::uint64_t {
                                                                            return 0U;
                                                                        }};

        WHEN("the filtered lookup is called")
        {
            auto const resolved = discovery.lookup_addresses_filtered("push.example.org", 443U);

            THEN("the public address is returned")
            {
                REQUIRE(resolved.ok);
                REQUIRE(resolved.addresses.size() == 1U);
                REQUIRE(resolved.addresses[0] == "203.0.113.1");
            }
        }
    }

    GIVEN("a cached discovery wrapping a network that returns a private address")
    {
        auto network = FilteringDiscoveryNetwork{};
        network.next_address = "127.0.0.1";
        auto discovery = merovingian::federation::CachedServerDiscovery{network, 60000U, []() -> std::uint64_t {
                                                                            return 0U;
                                                                        }};

        WHEN("the filtered lookup is called for an attacker-influenced URL host")
        {
            auto const resolved = discovery.lookup_addresses_filtered("attacker.example.org", 443U);

            THEN("the result fails closed before any outbound connection is attempted")
            {
                REQUIRE_FALSE(resolved.ok);
                REQUIRE(resolved.addresses.empty());
                REQUIRE_FALSE(resolved.reason.empty());
            }
        }
    }
}

SCENARIO("Federation security boundary notes document SSRF and DNS rebinding controls", "[federation][security]")
{
    GIVEN("security boundary notes")
    {
        WHEN("notes are returned")
        {
            auto const notes = merovingian::federation::federation_security_boundary_notes();

            THEN("SSRF, DNS rebinding, and trust boundaries are documented")
            {
                REQUIRE(notes.size() == 3U);
                REQUIRE(notes[0].find("SSRF") != std::string::npos);
                REQUIRE(notes[1].find("DNS rebinding") != std::string::npos);
                REQUIRE(notes[2].find("Trust boundary") != std::string::npos);
            }
        }
    }
}
