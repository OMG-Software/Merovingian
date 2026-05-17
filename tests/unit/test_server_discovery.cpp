// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/server_discovery.hpp"

#include <catch2/catch_test_macros.hpp>

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

SCENARIO("Server discovery resolves a direct server name without well-known", "[federation][discovery]")
{
    GIVEN("a server name with no well-known delegation")
    {
        WHEN("discovery is attempted against a local mock")
        {
            auto const result = merovingian::federation::discover_server("example.org", "https://example.org:8448");

            THEN("the resolved host and port are returned from the direct URL")
            {
                REQUIRE(result.resolved_host == "example.org");
                REQUIRE(result.resolved_port == 8448U);
            }
        }
    }
}

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
                REQUIRE(result.resolved_host == "delegated.example.org");
                REQUIRE(result.resolved_port == 8448U);
            }
        }
    }
}

SCENARIO("Server discovery rejects private IP addresses", "[federation][discovery][security]")
{
    GIVEN("a server name that resolves to a private address")
    {
        WHEN("discovery is attempted")
        {
            THEN("loopback addresses are rejected")
            {
                auto const result = merovingian::federation::discover_server("evil.org", "https://127.0.0.1:8448");
                REQUIRE_FALSE(result.discovery_allowed);
                REQUIRE(result.reason.find("private") != std::string::npos);
            }
        }
    }
}

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
                REQUIRE(result.server_name == "matrix.example.org");
                REQUIRE(result.resolved_host == "matrix.example.org");
                REQUIRE(result.resolved_port == 8448U);
                REQUIRE(result.tls_required);
                REQUIRE(result.discovery_allowed);
            }
        }
    }
}

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
                REQUIRE(result.tls_required);
            }
        }
    }
}

SCENARIO("Server discovery validates server name format", "[federation][discovery]")
{
    GIVEN("invalid server names")
    {
        WHEN("an empty server name is discovered")
        {
            auto const result = merovingian::federation::discover_server("", "https://:8448");

            THEN("discovery is rejected")
            {
                REQUIRE_FALSE(result.discovery_allowed);
            }
        }
    }
}

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
                REQUIRE(destination.server_name == "remote.example.org");
                REQUIRE(destination.consecutive_failures == 1U);
                REQUIRE(destination.retry_after_ts == 5000U);
            }
        }
    }
}

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
                REQUIRE(network.fetched_server == "example.org");
                REQUIRE(network.fetched_timeout == 7U);
                REQUIRE(result.discovery_allowed);
                REQUIRE(result.well_known_host == "fed.example.net");
                REQUIRE(result.resolved_host == "fed.example.net");
                REQUIRE(result.resolved_port == 9448U);
                auto const expected_addresses = std::vector<std::string>{"203.0.113.10", "2001:db8::10"};
                REQUIRE(result.pinned_addresses == expected_addresses);
            }
        }
    }
}

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
                REQUIRE(network.last_srv_lookup == "_matrix-fed._tcp.example.org");
                REQUIRE(result.discovery_allowed);
                REQUIRE(result.resolved_host == "srv.example.net");
                REQUIRE(result.resolved_port == 9449U);
                auto const expected_addresses = std::vector<std::string>{"198.51.100.22"};
                REQUIRE(result.pinned_addresses == expected_addresses);
            }
        }
    }
}

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
                REQUIRE_FALSE(rejected_v4.discovery_allowed);
                REQUIRE(rejected_v4.pinned_addresses.empty());
                REQUIRE(rejected_v4.reason.find("private") != std::string::npos);
                REQUIRE_FALSE(rejected_v6.discovery_allowed);
                REQUIRE(rejected_v6.pinned_addresses.empty());
                REQUIRE(rejected_v6.reason.find("private") != std::string::npos);
            }
        }
    }
}
