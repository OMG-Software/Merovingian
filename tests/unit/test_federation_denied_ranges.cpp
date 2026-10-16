// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/cached_server_discovery.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/federation/security.hpp"
#include "merovingian/federation/server_discovery.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <tuple>
#include <vector>

namespace
{
// Exercise the policy-aware production APIs directly.
[[nodiscard]] auto discover_with_policy(std::string_view name, merovingian::federation::ServerDiscoveryNetwork& network,
                                        std::vector<std::string> const& policy)
    -> merovingian::federation::ServerDiscoveryResult
{
    return discover_server(name, network, 1U, policy);
}

[[nodiscard]] auto allowed_with_policy(std::vector<std::string> const& addresses,
                                       std::vector<std::string> const& policy) -> bool
{
    return merovingian::federation::address_set_allowed(addresses, policy);
}

class RangeDiscoveryNetwork final : public merovingian::federation::ServerDiscoveryNetwork
{
public:
    using ServerDiscoveryNetwork::ServerDiscoveryNetwork;
    merovingian::federation::WellKnownServerResult well_known{};
    std::vector<merovingian::federation::SrvRecord> srv{};
    std::vector<std::string> addresses{"203.0.113.10"};

    [[nodiscard]] auto fetch_well_known(std::string_view,
                                        std::uint32_t) -> merovingian::federation::WellKnownServerResult override
    {
        return well_known;
    }
    [[nodiscard]] auto lookup_srv(std::string_view) -> std::vector<merovingian::federation::SrvRecord> override
    {
        return srv;
    }
    [[nodiscard]] auto lookup_addresses(std::string_view,
                                        std::uint16_t) -> merovingian::federation::ResolvedAddressSet override
    {
        return {true, addresses, {}};
    }
};
} // namespace

SCENARIO("network-owned denied ranges survive cached and uncached call paths", "[federation][out-8][range-wiring]")
{
    GIVEN("the discovery network owns the operator's configured public CIDR")
    {
        auto const policy = std::vector<std::string>{"203.0.113.0/24"};
        auto network = RangeDiscoveryNetwork{policy};
        auto cached = merovingian::federation::CachedServerDiscovery{network, 60000U, [] {
                                                                         return 1000U;
                                                                     }};
        WHEN("callers use their existing APIs without passing an additional policy")
        {
            THEN("discovery, cache hits, filtered URLs, and redirect resolution all retain the restriction")
            {
                REQUIRE_FALSE(
                    merovingian::federation::discover_server("origin.example:8448", network, 1U).discovery_allowed);
                REQUIRE_FALSE(cached.discover("origin.example:8448", 1U).discovery_allowed);
                REQUIRE_FALSE(cached.discover("origin.example:8448", 1U).discovery_allowed);
                REQUIRE_FALSE(cached.lookup_addresses_filtered("origin.example", 443U).ok);
                REQUIRE_FALSE(merovingian::federation::resolve_federation_destination("redirect.example", 443U, network)
                                  .discovery_allowed);
                REQUIRE_FALSE(merovingian::federation::discover_server("origin.example:8448", network, 1U,
                                                                       std::vector<std::string>{})
                                  .discovery_allowed);
            }
        }
    }
}

SCENARIO("production discovery applies configured ranges before well-known HTTP", "[federation][out-8][range-wiring]")
{
    GIVEN("a production network with a configured public CIDR block")
    {
        auto const policy = std::vector<std::string>{"203.0.113.0/24"};
        auto network = merovingian::federation::make_system_server_discovery_network(policy);
        WHEN("an IP literal in the range is used as a well-known and federation destination")
        {
            THEN("both pre-connect paths refuse the literal without an HTTP request")
            {
                REQUIRE(network->denied_ip_ranges() == policy);
                REQUIRE_FALSE(network->fetch_well_known("203.0.113.10", 1U).ok);
                REQUIRE_FALSE(merovingian::federation::discover_server("203.0.113.10", *network, 1U).discovery_allowed);
            }
        }
    }
}

SCENARIO("configured public CIDRs refuse every federation destination branch", "[federation][out-8][range-discovery]")
{
    GIVEN("the runtime policy denies 203.0.113.0/24")
    {
        auto config = merovingian::config::Config{};
        config.security().federation.deny_ip_ranges.push_back("203.0.113.0/24");
        auto const policy = merovingian::federation::make_runtime_federation_config(config).deny_ip_ranges;
        auto network = RangeDiscoveryNetwork{};
        WHEN("discovery resolves the forbidden address through any Matrix v1.19 branch")
        {
            auto const branches = std::vector<std::tuple<std::string, std::string, bool>>{
                {"203.0.113.10",        "",                       false},
                {"origin.example:8448", "",                       false},
                {"origin.example",      "",                       false},
                {"origin.example",      "",                       true },
                {"origin.example",      "203.0.113.10",           false},
                {"origin.example",      "delegated.example:8448", false},
                {"origin.example",      "delegated.example",      false},
                {"origin.example",      "delegated.example",      true },
            };
            THEN("all eight branches refuse discovery and expose no connectable pins")
            {
                for (auto const& [server, delegated, use_srv] : branches)
                {
                    CAPTURE(server, delegated, use_srv);
                    network.well_known = delegated.empty()
                                             ? merovingian::federation::WellKnownServerResult{}
                                             : merovingian::federation::WellKnownServerResult{
                                                   true, true, "{\"m.server\":\"" + delegated + "\"}", {}};
                    network.srv = use_srv ? std::vector<merovingian::federation::SrvRecord>{{"srv.example", 8448U, 0U, 0U}}
                        : std::vector<merovingian::federation::SrvRecord>{};
                    auto const result = discover_with_policy(server, network, policy);
                    REQUIRE_FALSE(result.discovery_allowed);
                    REQUIRE(result.pinned_addresses.empty());
                }
            }
        }
    }
}

SCENARIO("configured IPv4 and IPv6 CIDRs match exact prefix boundaries", "[federation][out-8][range-boundaries]")
{
    GIVEN("public IPv4 and IPv6 prefixes including partial octets")
    {
        auto const policy = std::vector<std::string>{"203.0.113.64/26", "2001:db8:1234:5680::/57"};
        WHEN("addresses just inside and outside the ranges are checked")
        {
            THEN("only the configured prefix and its inclusive endpoints are denied")
            {
                REQUIRE(allowed_with_policy({"203.0.113.63"}, policy));
                REQUIRE_FALSE(allowed_with_policy({"203.0.113.64"}, policy));
                REQUIRE_FALSE(allowed_with_policy({"203.0.113.127"}, policy));
                REQUIRE(allowed_with_policy({"203.0.113.128"}, policy));
                REQUIRE(allowed_with_policy({"2001:db8:1234:567f:ffff:ffff:ffff:ffff"}, policy));
                REQUIRE_FALSE(allowed_with_policy({"2001:db8:1234:5680::"}, policy));
                REQUIRE_FALSE(allowed_with_policy({"2001:db8:1234:56ff:ffff:ffff:ffff:ffff"}, policy));
                REQUIRE(allowed_with_policy({"2001:db8:1234:5700::"}, policy));
                REQUIRE_FALSE(allowed_with_policy({"8.8.8.8", "203.0.113.64"}, policy));
            }
        }
    }
}

SCENARIO("configured CIDRs add restrictions but cannot bypass built-in SSRF blocks",
         "[federation][out-8][range-builtins]")
{
    GIVEN("an empty or unrelated configured policy")
    {
        auto policy = std::vector<std::string>{};
        WHEN("private and reserved destinations are checked")
        {
            policy = {"203.0.113.0/24"};
            THEN("every existing mandatory block still applies")
            {
                for (auto const& address :
                     {"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.0.1", "169.254.0.1", "100.64.0.1", "224.0.0.1",
                      "240.0.0.1", "::1", "fc00::1", "fe80::1", "ff02::1", "64:ff9b::1", "::ffff:127.0.0.1"})
                {
                    CAPTURE(address);
                    REQUIRE_FALSE(allowed_with_policy({address}, policy));
                }
                REQUIRE(allowed_with_policy({"8.8.8.8", "2001:4860:4860::8888"}, policy));
            }
        }
    }
}

SCENARIO("configured CIDRs handle full and zero prefixes and mapped IPv4", "[federation][out-8][range-boundaries]")
{
    GIVEN("CIDRs with the minimum and maximum legal prefix lengths")
    {
        WHEN("exact literals and mapped IPv4 forms are checked")
        {
            THEN("prefix zero matches a family and exact prefixes match only one address")
            {
                REQUIRE_FALSE(allowed_with_policy({"8.8.8.8"}, std::vector<std::string>{"0.0.0.0/0"}));
                REQUIRE_FALSE(allowed_with_policy({"2001:db8::1"}, std::vector<std::string>{"::/0"}));
                REQUIRE_FALSE(allowed_with_policy({"8.8.8.8"}, std::vector<std::string>{"8.8.8.8/32"}));
                REQUIRE(allowed_with_policy({"8.8.8.9"}, std::vector<std::string>{"8.8.8.8/32"}));
                REQUIRE_FALSE(allowed_with_policy({"2001:db8::1"}, std::vector<std::string>{"2001:db8::1/128"}));
                REQUIRE(allowed_with_policy({"2001:db8::2"}, std::vector<std::string>{"2001:db8::1/128"}));
                REQUIRE_FALSE(allowed_with_policy({"::ffff:203.0.113.10"}, std::vector<std::string>{"203.0.113.0/24"}));
            }
        }
    }
}
