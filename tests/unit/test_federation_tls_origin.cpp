// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |              FEDERATION TLS ORIGIN VALIDATION TESTS                     |
// |                                                                         |
// |  Spec: Matrix Server-Server API v1.19, Sec. 2 Resolving server names    |
// |  URL:  ../../docs/matrix-v1.19-spec/server-server-api.md                |
// |        #resolving-server-names                                          |
// +-------------------------------------------------------------------------+

#include "merovingian/federation/server_discovery.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>
#include <vector>

namespace
{

[[nodiscard]] auto make_result(std::string_view server_name, std::string_view resolved_host,
                               std::uint16_t resolved_port, bool discovery_allowed, bool tls_required,
                               std::string_view well_known_host = {}) -> merovingian::federation::ServerDiscoveryResult
{
    auto result = merovingian::federation::ServerDiscoveryResult{};
    result.server_name = std::string{server_name};
    result.resolved_host = std::string{resolved_host};
    result.resolved_port = resolved_port;
    result.discovery_allowed = discovery_allowed;
    result.tls_required = tls_required;
    result.well_known_host = std::string{well_known_host};
    return result;
}

} // namespace

SCENARIO("TLS origin validation accepts direct server-name matches", "[federation][discovery][security]")
{
    GIVEN("a discovery result where the resolved host matches the server name")
    {
        auto const result = make_result("example.org", "example.org", 8448U, true, true);

        WHEN("the TLS origin is validated")
        {
            auto const decision = merovingian::federation::validate_federation_tls_origin("example.org", result);

            THEN("the destination is accepted")
            {
                REQUIRE(decision.valid);
            }
        }
    }
}

SCENARIO("TLS origin validation rejects mismatched direct hosts", "[federation][discovery][security]")
{
    GIVEN("a discovery result where the resolved host differs from the server name")
    {
        auto const result = make_result("example.org", "other.org", 8448U, true, true);

        WHEN("the TLS origin is validated")
        {
            auto const decision = merovingian::federation::validate_federation_tls_origin("example.org", result);

            THEN("the destination is rejected")
            {
                REQUIRE_FALSE(decision.valid);
                REQUIRE_FALSE(decision.reason.empty());
            }
        }
    }
}

SCENARIO("TLS origin validation accepts well-known delegation when hosts match", "[federation][discovery][security]")
{
    GIVEN("a discovery result produced by well-known delegation")
    {
        auto const result = make_result("example.org", "fed.example.net", 8448U, true, true, "fed.example.net");

        WHEN("the TLS origin is validated")
        {
            auto const decision = merovingian::federation::validate_federation_tls_origin("example.org", result);

            THEN("the delegated destination is accepted")
            {
                REQUIRE(decision.valid);
            }
        }
    }
}

SCENARIO("TLS origin validation rejects well-known delegation host mismatch", "[federation][discovery][security]")
{
    GIVEN("a discovery result where well-known host and resolved host disagree")
    {
        auto const result = make_result("example.org", "resolved.example.net", 8448U, true, true, "fed.example.net");

        WHEN("the TLS origin is validated")
        {
            auto const decision = merovingian::federation::validate_federation_tls_origin("example.org", result);

            THEN("the destination is rejected")
            {
                REQUIRE_FALSE(decision.valid);
                REQUIRE_FALSE(decision.reason.empty());
            }
        }
    }
}

SCENARIO("TLS origin validation rejects IP literal destinations unless the server name matches",
         "[federation][discovery][security]")
{
    GIVEN("a numeric IP resolved host")
    {
        auto const result = make_result("example.org", "203.0.113.10", 8448U, true, true);

        WHEN("validated against a DNS server name")
        {
            auto const decision = merovingian::federation::validate_federation_tls_origin("example.org", result);

            THEN("the destination is rejected")
            {
                REQUIRE_FALSE(decision.valid);
            }
        }

        WHEN("validated against the same IP literal server name")
        {
            auto const decision = merovingian::federation::validate_federation_tls_origin("203.0.113.10", result);

            THEN("the destination is accepted")
            {
                REQUIRE(decision.valid);
            }
        }
    }
}

SCENARIO("TLS origin validation requires TLS and allowed discovery", "[federation][discovery][security]")
{
    GIVEN("a non-TLS destination")
    {
        auto const result = make_result("example.org", "example.org", 8008U, true, false);

        WHEN("validated")
        {
            auto const decision = merovingian::federation::validate_federation_tls_origin("example.org", result);

            THEN("it is rejected")
            {
                REQUIRE_FALSE(decision.valid);
            }
        }
    }

    GIVEN("a disallowed discovery result")
    {
        auto const result = make_result("example.org", "example.org", 8448U, false, true);

        WHEN("validated")
        {
            auto const decision = merovingian::federation::validate_federation_tls_origin("example.org", result);

            THEN("it is rejected")
            {
                REQUIRE_FALSE(decision.valid);
            }
        }
    }
}

SCENARIO("TLS origin validation rejects invalid server names", "[federation][discovery][security]")
{
    GIVEN("an empty server name")
    {
        auto const result = make_result("", "example.org", 8448U, true, true);

        WHEN("validated")
        {
            auto const decision = merovingian::federation::validate_federation_tls_origin("", result);

            THEN("it is rejected")
            {
                REQUIRE_FALSE(decision.valid);
            }
        }
    }
}

SCENARIO("TLS origin validation handles IPv6 literals consistently", "[federation][discovery][security]")
{
    GIVEN("a numeric IPv6 resolved host")
    {
        auto const result = make_result("2001:db8::1", "2001:db8::1", 8448U, true, true);

        WHEN("validated against the same IP literal server name")
        {
            auto const decision = merovingian::federation::validate_federation_tls_origin("2001:db8::1", result);

            THEN("the destination is accepted")
            {
                REQUIRE(decision.valid);
            }
        }

        WHEN("validated against a different DNS name")
        {
            auto const decision = merovingian::federation::validate_federation_tls_origin("example.org", result);

            THEN("the destination is rejected")
            {
                REQUIRE_FALSE(decision.valid);
            }
        }
    }
}

SCENARIO("TLS origin validation rejects an empty resolved host", "[federation][discovery][security]")
{
    GIVEN("a discovery result with no resolved host")
    {
        auto const result = make_result("example.org", "", 8448U, true, true);

        WHEN("validated")
        {
            auto const decision = merovingian::federation::validate_federation_tls_origin("example.org", result);

            THEN("it is rejected")
            {
                REQUIRE_FALSE(decision.valid);
                REQUIRE_FALSE(decision.reason.empty());
            }
        }
    }
}
