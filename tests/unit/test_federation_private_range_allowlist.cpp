// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// security.federation.allow_private_ip_ranges (ADR-0231) at the federation
// boundary. An allowlisted private network is reachable for federation
// (discovery, well-known, key fetch, the inbound origin check); loopback,
// link-local, CGNAT, multicast and reserved space never are, whatever the
// list says; and callers that pass no allowance (URL preview, media
// redirects) keep the full block even when the shared discovery network
// carries one.

#include "merovingian/config/config.hpp"
#include "merovingian/federation/cached_server_discovery.hpp"
#include "merovingian/federation/runtime_federation.hpp"
#include "merovingian/federation/security.hpp"
#include "merovingian/federation/server_discovery.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

namespace
{
using merovingian::federation::address_set_allowed;

auto const default_deny = merovingian::config::Config{}.security().federation.deny_ip_ranges;

class PrivateDiscoveryNetwork final : public merovingian::federation::ServerDiscoveryNetwork
{
public:
    using ServerDiscoveryNetwork::ServerDiscoveryNetwork;
    std::vector<std::string> addresses{"172.18.0.3"};

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
        return {true, addresses, {}};
    }
};
} // namespace

SCENARIO("An allowlisted private network passes the federation address policy",
         "[federation][security][private-allowlist]")
{
    GIVEN("the Docker bridge range is allowlisted and the default deny list is configured")
    {
        auto const allowance = std::vector<std::string>{"172.16.0.0/12"};

        WHEN("addresses inside and outside the allowlisted network are checked")
        {
            auto const bridge = address_set_allowed({"172.18.0.3"}, default_deny, allowance);
            auto const mapped = address_set_allowed({"::ffff:172.18.0.3"}, default_deny, allowance);
            auto const other_private = address_set_allowed({"10.0.0.1"}, default_deny, allowance);
            auto const public_address = address_set_allowed({"203.0.113.10"}, default_deny, allowance);

            THEN("only the allowlisted network is opened, public space is unchanged")
            {
                REQUIRE(bridge);
                REQUIRE(mapped);
                REQUIRE_FALSE(other_private);
                REQUIRE(public_address);
            }
        }

        WHEN("no allowance is passed")
        {
            auto const bridge = address_set_allowed({"172.18.0.3"}, default_deny);

            THEN("the built-in block still refuses the address")
            {
                REQUIRE_FALSE(bridge);
            }
        }

        WHEN("one address of a set is allowlisted and another is loopback")
        {
            auto const mixed = address_set_allowed({"172.18.0.3", "127.0.0.1"}, default_deny, allowance);

            THEN("the whole set is refused")
            {
                REQUIRE_FALSE(mixed);
            }
        }
    }
}

SCENARIO("An allowance never opens loopback, link-local, CGNAT or reserved space",
         "[federation][security][private-allowlist]")
{
    GIVEN("allowances that try to name non-private space, including malformed ones")
    {
        auto const allowance = std::vector<std::string>{
            "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/0", "224.0.0.0/4",
            "::1/128",     "fe80::/10",      "::/0",          "garbage",   "10.0.0.0/99",
        };

        WHEN("addresses in those ranges are checked")
        {
            THEN("each is still refused")
            {
                for (auto const* address :
                     {"127.0.0.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "240.0.0.1", "::1",
                      "fe80::1", "64:ff9b::1", "10.0.0.1", "::ffff:127.0.0.1"})
                {
                    INFO(address);
                    REQUIRE_FALSE(address_set_allowed({address}, {}, allowance));
                    REQUIRE_FALSE(merovingian::federation::ip_address_in_allowed_private_range(address, allowance));
                }
            }
        }
    }

    GIVEN("an allowance of the whole IPv6 unique-local block")
    {
        auto const allowance = std::vector<std::string>{"fc00::/7"};

        WHEN("a ULA address and a link-local address are checked")
        {
            auto const ula = address_set_allowed({"fd00::5"}, default_deny, allowance);
            auto const link_local = address_set_allowed({"fe80::5"}, default_deny, allowance);

            THEN("the ULA address passes and link-local does not")
            {
                REQUIRE(ula);
                REQUIRE_FALSE(link_local);
            }
        }
    }
}

SCENARIO("The inbound origin check honours the allowance", "[federation][security][private-allowlist]")
{
    GIVEN("a remote origin whose discovered address is on the Docker bridge")
    {
        auto remote = merovingian::federation::RemoteServerRecord{};
        remote.server_name = "host.docker.internal:40123";
        remote.resolved_host = "host.docker.internal";
        remote.well_known_host = "host.docker.internal";
        remote.resolved_addresses = {"172.17.0.1"};

        WHEN("the discovery policy is evaluated with and without the allowance")
        {
            auto const allowed =
                merovingian::federation::federation_discovery_policy(remote, std::vector<std::string>{"172.16.0.0/12"});
            auto const refused = merovingian::federation::federation_discovery_policy(remote);

            THEN("only the allowlisted evaluation accepts the origin")
            {
                REQUIRE(allowed.accepted);
                REQUIRE_FALSE(refused.accepted);
                REQUIRE(refused.reason == "remote address is private or loopback");
            }
        }
    }
}

// The discovery network is shared: federation discovery, the cached front
// end, and callers outside federation (pushers, identity servers, URL preview)
// all resolve through it. The allowance it carries must open the allowlisted
// network to the federation paths only, and never let loopback through, so
// each path is checked here against the same network (ADR-0231).
SCENARIO("Federation discovery reaches an allowlisted peer by name and by literal",
         "[federation][discovery][private-allowlist]")
{
    GIVEN("a discovery network that carries the allowance and resolves hs2 to the Docker bridge")
    {
        auto network = PrivateDiscoveryNetwork{default_deny, std::vector<std::string>{"172.16.0.0/12"}};

        WHEN("hs2, hs2:8448 and an IP literal are discovered")
        {
            // Each server-name form takes its own branch of discover_server:
            // SRV and well-known lookup for a bare name, a direct connection for
            // an explicit port, and no resolution at all for an IP literal.
            auto const by_name = merovingian::federation::discover_server("hs2", network, 1U);
            auto const by_port = merovingian::federation::discover_server("hs2:8448", network, 1U);
            auto const by_literal = merovingian::federation::discover_server("172.18.0.3:8448", network, 1U);

            THEN("every branch is allowed and pinned to the bridge address")
            {
                REQUIRE(network.allowed_private_ip_ranges() == std::vector<std::string>{"172.16.0.0/12"});
                for (auto const* result : {&by_name, &by_port, &by_literal})
                {
                    REQUIRE(result->discovery_allowed);
                    REQUIRE(result->pinned_addresses == std::vector<std::string>{"172.18.0.3"});
                }
            }
        }

        WHEN("the cached front end discovers hs2 twice")
        {
            // The first call misses the cache and the second hits it; both must
            // carry the allowance, or a cached result would decide differently.
            auto cached = merovingian::federation::CachedServerDiscovery{network, 60000U, [] {
                                                                             return 1000U;
                                                                         }};
            auto const first = cached.discover("hs2", 1U);
            auto const second = cached.discover("hs2", 1U);

            THEN("both the miss and the hit are allowed")
            {
                REQUIRE(first.discovery_allowed);
                REQUIRE(second.discovery_allowed);
            }
        }

        WHEN("a non-federation caller resolves the same host without passing an allowance")
        {
            // URL preview and media redirects call resolve_federation_destination
            // without an allowance; the one the network carries must not reach them.
            auto const preview_style = merovingian::federation::resolve_federation_destination("hs2", 443U, network);
            auto const literal = merovingian::federation::resolve_federation_destination("172.18.0.3", 443U, network);

            THEN("the network's federation allowance does not leak to it")
            {
                REQUIRE_FALSE(preview_style.discovery_allowed);
                REQUIRE_FALSE(literal.discovery_allowed);
            }
        }

        WHEN("a pusher gateway or identity server host is looked up through the shared cache")
        {
            // lookup_addresses_filtered serves pushers and identity servers, which
            // fetch URLs a user chose: an SSRF opening if the allowance applied.
            auto cached = merovingian::federation::CachedServerDiscovery{network, 60000U, [] {
                                                                             return 1000U;
                                                                         }};
            auto const resolved = cached.lookup_addresses_filtered("hs2", 443U);

            THEN("the federation allowance does not apply and the bridge address is refused")
            {
                REQUIRE_FALSE(resolved.ok);
                REQUIRE(resolved.addresses.empty());
            }
        }

        WHEN("the bridge address is replaced by loopback")
        {
            // A name that resolves to loopback stays refused: the allowance names
            // only private networks, never the host itself.
            network.addresses = {"127.0.0.1"};
            auto const result = merovingian::federation::discover_server("hs2", network, 1U);

            THEN("discovery is refused")
            {
                REQUIRE_FALSE(result.discovery_allowed);
                REQUIRE(result.pinned_addresses.empty());
            }
        }
    }

    GIVEN("the same network without an allowance")
    {
        auto network = PrivateDiscoveryNetwork{default_deny};

        WHEN("hs2 is discovered")
        {
            auto const result = merovingian::federation::discover_server("hs2", network, 1U);

            THEN("the built-in block refuses it")
            {
                REQUIRE_FALSE(result.discovery_allowed);
            }
        }
    }

    GIVEN("the production network built with an allowance")
    {
        auto const allowance = std::vector<std::string>{"192.168.65.0/24"};
        auto const network = merovingian::federation::make_system_server_discovery_network(default_deny, allowance);

        WHEN("its policy is read")
        {
            THEN("it carries both the deny list and the allowance")
            {
                REQUIRE(network->denied_ip_ranges() == default_deny);
                REQUIRE(network->allowed_private_ip_ranges() == allowance);
            }
        }
    }
}

SCENARIO("The configured allowance reaches the runtime federation config", "[federation][runtime][private-allowlist]")
{
    GIVEN("a config that allowlists the Docker bridge")
    {
        auto config = merovingian::config::Config{};
        config.security().federation.allow_private_ip_ranges = {"172.16.0.0/12"};

        WHEN("the runtime federation config is built")
        {
            auto const runtime = merovingian::federation::make_runtime_federation_config(config);

            THEN("the allowance is carried unchanged")
            {
                REQUIRE(runtime.allow_private_ip_ranges == std::vector<std::string>{"172.16.0.0/12"});
            }
        }
    }
}
