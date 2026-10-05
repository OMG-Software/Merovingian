// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/security.hpp"
#include "merovingian/federation/server_discovery.hpp"
#include "merovingian/homeserver/media_service.hpp"
#include "merovingian/http/outbound_client.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace
{

class CountingDiscoveryNetwork final : public merovingian::federation::ServerDiscoveryNetwork
{
public:
    std::uint32_t fetch_well_known_calls{0U};
    std::uint32_t srv_calls{0U};
    std::uint32_t address_calls{0U};

    [[nodiscard]] auto fetch_well_known(std::string_view,
                                        std::uint32_t) -> merovingian::federation::WellKnownServerResult override
    {
        ++fetch_well_known_calls;
        return {};
    }

    [[nodiscard]] auto lookup_srv(std::string_view) -> std::vector<merovingian::federation::SrvRecord> override
    {
        ++srv_calls;
        return {};
    }

    [[nodiscard]] auto lookup_addresses(std::string_view,
                                        std::uint16_t) -> merovingian::federation::ResolvedAddressSet override
    {
        ++address_calls;
        return {};
    }
};

} // namespace

SCENARIO("Outbound request validation rejects URL forms that can split the pin authority",
         "[http][outbound][security][security_audit_outbound]")
{
    GIVEN("HTTPS targets with a non-empty set of pinned addresses")
    {
        auto const invalid_urls = std::array<std::string, 11U>{
            "https://user@matrix.example.org/path",
            "https://matrix.example.org/path#fragment",
            "https://matrix.example.org/path#",
            "https://matrix.example.org\\@attacker.example/path",
            "https://matrix%2eexample.org/path",
            "https://matrix.example.org:0/path",
            "https://matrix.example.org:65536/path",
            "https://matrix.example.org:not-a-port/path",
            "https://[fe80::1%25eth0]/path",
            "https://[::::]/path",
            std::string{"https://matrix.example.org/"} + '\0' + "path",
        };

        WHEN("each URL is validated before transfer setup")
        {
            THEN("every ambiguous, malformed, credentialed, or fragment-bearing URL is refused")
            {
                for (auto const& url : invalid_urls)
                {
                    auto request = merovingian::http::OutboundRequest{};
                    request.url = url;
                    request.pinned_addresses = {"203.0.113.10"};
                    REQUIRE(merovingian::http::validate_outbound_request(request) ==
                            merovingian::http::OutboundError::invalid_url);
                }
            }
        }
    }
}

SCENARIO("Outbound request validation keeps valid encoded paths and queries available",
         "[http][outbound][security][security_audit_outbound]")
{
    GIVEN("a normal HTTPS authority with an encoded path and query")
    {
        auto request = merovingian::http::OutboundRequest{};
        request.url = "https://matrix.example.org/%2e%2e/_matrix/key/v2/server?version=1";
        request.pinned_addresses = {"203.0.113.10"};

        WHEN("the outbound request is validated")
        {
            THEN("the request remains valid and the signed request target can be preserved")
            {
                REQUIRE(merovingian::http::validate_outbound_request(request) ==
                        merovingian::http::OutboundError::none);
            }
        }
    }
}

SCENARIO("Federation server-name validation follows Matrix grammar before discovery",
         "[federation][server-name][security][security_audit_outbound]")
{
    auto const valid_names = std::array<std::string_view, 10U>{
        "localhost",          "a", "123", "1.2", "A.B.C", "example.org.", "1.2.3.4", "001.002.003.004", "[2001:db8::1]",
        "[2001:db8::1]:8448",
    };
    auto const invalid_names = std::array<std::string_view, 11U>{
        "matrix.example@evil.org",
        "matrix.example?evil",
        "matrix.example#evil",
        "matrix .example.org",
        "matrix.example.org:bad",
        "matrix.example.org:0",
        "matrix.example.org:65536",
        "[::::]",
        "matrix\\example.org",
        "matrix%2eexample.org",
        "999.1.1.1",
    };

    GIVEN("server names allowed by the Matrix v1.19 grammar, including single-label DNS names and IPv6 literals")
    {
        WHEN("each name is tested by the federation validator")
        {
            THEN("every syntactically valid Matrix server name is accepted")
            {
                for (auto const name : valid_names)
                {
                    REQUIRE(merovingian::federation::server_name_is_valid(name));
                }
            }
        }
    }

    GIVEN("malformed Matrix server-name authorities")
    {
        WHEN("each name is tested by the federation validator")
        {
            THEN("every forbidden delimiter, malformed port, or invalid IP literal is rejected")
            {
                for (auto const name : invalid_names)
                {
                    REQUIRE_FALSE(merovingian::federation::server_name_is_valid(name));
                }
            }
        }
    }

    GIVEN("malformed remote names and a discovery network that counts every lookup")
    {
        auto network = CountingDiscoveryNetwork{};

        WHEN("discovery is requested for every malformed name")
        {
            THEN("the name is refused before well-known, SRV, or address resolution")
            {
                for (auto const name : invalid_names)
                {
                    auto const result = merovingian::federation::discover_server(name, network, 1U);
                    REQUIRE_FALSE(result.discovery_allowed);
                }
                REQUIRE(network.fetch_well_known_calls == 0U);
                REQUIRE(network.srv_calls == 0U);
                REQUIRE(network.address_calls == 0U);
            }
        }
    }
}

SCENARIO("Media redirect validation refuses a fragment in an absolute HTTPS Location",
         "[homeserver][media][security][security_audit_outbound]")
{
    GIVEN("a media redirect URL that appends a fragment to a public hostname")
    {
        auto network = CountingDiscoveryNetwork{};

        WHEN("the media redirect is validated")
        {
            auto const result =
                merovingian::homeserver::resolve_media_redirect_url("https://cdn.example.org/media/item#", network);

            THEN("the redirect is refused before any DNS or federation lookup")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(network.fetch_well_known_calls == 0U);
                REQUIRE(network.srv_calls == 0U);
                REQUIRE(network.address_calls == 0U);
            }
        }
    }
}
