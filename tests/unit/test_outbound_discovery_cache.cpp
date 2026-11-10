// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// A6 (Complement run 9): every federated join paid the full .well-known + SRV +
// DNS cascade twice (make_join and send_join) although the server's discovery
// result was cached for 60 s for every other caller. A destination's discovery
// result is reusable for the cache's lifetime; a failure is not, because a
// retried join must not be refused for a minute after the peer comes back.
//
// Spec: ../../docs/matrix-v1.19-spec/server-server-api.md#resolving-server-names
// ("Responses (successful or otherwise) to the /.well-known endpoint should be
// cached by the requesting server"; errors "up to an hour").
#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/federation/CachedServerDiscovery.hpp"
#include "merovingian/federation/DiscoveryCachePolicy.hpp"
#include "merovingian/federation/OutboundTransaction.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/KeyServerCache.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"
#include "merovingian/homeserver/room_service.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace
{
using merovingian::federation::DiscoveryCachePolicy;

class ScriptedDiscoveryNetwork final : public merovingian::federation::ServerDiscoveryNetwork
{
public:
    // Calls that reached the network, across all three lookups.
    std::atomic<std::uint64_t> calls{0U};
    std::atomic<bool> reachable{true};

    [[nodiscard]] auto fetch_well_known(std::string_view, std::uint32_t)
        -> merovingian::federation::WellKnownServerResult override
    {
        ++calls;
        return {};
    }
    [[nodiscard]] auto lookup_srv(std::string_view) -> std::vector<merovingian::federation::SrvRecord> override
    {
        ++calls;
        return {};
    }
    [[nodiscard]] auto lookup_addresses(std::string_view, std::uint16_t)
        -> merovingian::federation::ResolvedAddressSet override
    {
        ++calls;
        auto const up = reachable.load();
        return {up, up ? std::vector<std::string>{"203.0.113.10"} : std::vector<std::string>{}, "unreachable"};
    }
};
} // namespace

SCENARIO("A cache serving only successes reuses a destination's discovery result",
         "[federation][discovery-cache][outbound][spec]")
{
    GIVEN("a discovery cache over a reachable destination")
    {
        auto network = ScriptedDiscoveryNetwork{};
        auto now = std::uint64_t{1000U};
        auto cached = merovingian::federation::CachedServerDiscovery{network, 60'000U, [&now] {
                                                                         return now;
                                                                     }};

        WHEN("the destination is resolved twice within the cache lifetime")
        {
            auto const first = cached.discover("remote.example.org:8448", 1U, DiscoveryCachePolicy::successes_only);
            auto const after_first = network.calls.load();
            now += 1'000U;
            auto const second = cached.discover("remote.example.org:8448", 1U, DiscoveryCachePolicy::successes_only);

            THEN("the second resolution reaches the network no more than the first did, and agrees with it")
            {
                REQUIRE(first.discovery_allowed);
                REQUIRE(second.discovery_allowed);
                REQUIRE(network.calls.load() == after_first);
                REQUIRE(second.pinned_addresses == first.pinned_addresses);
                REQUIRE(second.resolved_host == first.resolved_host);
            }
        }

        WHEN("the destination is resolved again after the cache lifetime")
        {
            REQUIRE(
                cached.discover("remote.example.org:8448", 1U, DiscoveryCachePolicy::successes_only).discovery_allowed);
            auto const after_first = network.calls.load();
            now += 60'000U;
            auto const later = cached.discover("remote.example.org:8448", 1U, DiscoveryCachePolicy::successes_only);

            THEN("it is resolved afresh, so pinned addresses never outlive the lifetime")
            {
                REQUIRE(later.discovery_allowed);
                REQUIRE(network.calls.load() > after_first);
            }
        }
    }
}

SCENARIO("A cache serving only successes never serves a remembered failure",
         "[federation][discovery-cache][outbound][spec]")
{
    GIVEN("a destination whose resolution failed and was remembered by a caller that accepts failures")
    {
        auto network = ScriptedDiscoveryNetwork{};
        network.reachable = false;
        auto cached = merovingian::federation::CachedServerDiscovery{network, 60'000U, [] {
                                                                         return 1'000U;
                                                                     }};
        REQUIRE_FALSE(cached.discover("remote.example.org:8448", 1U).discovery_allowed);
        auto const after_failure = network.calls.load();
        REQUIRE_FALSE(cached.discover("remote.example.org:8448", 1U).discovery_allowed);
        REQUIRE(network.calls.load() == after_failure);

        WHEN("the destination has come back and a join resolves it")
        {
            network.reachable = true;
            auto const result = cached.discover("remote.example.org:8448", 1U, DiscoveryCachePolicy::successes_only);

            THEN("the join sees the live answer, and later callers share it")
            {
                REQUIRE(result.discovery_allowed);
                REQUIRE(network.calls.load() > after_failure);
                auto const calls = network.calls.load();
                REQUIRE(cached.discover("remote.example.org:8448", 1U).discovery_allowed);
                REQUIRE(network.calls.load() == calls);
            }
        }
    }
}
