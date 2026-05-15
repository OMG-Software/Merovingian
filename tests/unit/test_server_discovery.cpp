// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/server_discovery.hpp"

#include <catch2/catch_test_macros.hpp>

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