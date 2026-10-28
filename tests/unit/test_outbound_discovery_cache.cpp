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
#include "merovingian/config/config.hpp"
#include "merovingian/federation/cached_server_discovery.hpp"
#include "merovingian/federation/outbound_transaction.hpp"
#include "merovingian/homeserver/room_service.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <sodium.h>

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

[[nodiscard]] auto runtime_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto join_exchange_call(merovingian::homeserver::HomeserverRuntime& runtime, std::string_view target)
    -> std::pair<bool, std::string>
{
    auto const transaction = merovingian::federation::OutboundTransaction{
        .destination = "remote.example.org:8448",
        .method = "GET",
        .target = std::string{target},
        .origin = "local.example.org",
        .body = {},
    };
    // No signing secret: the call resolves the destination, then refuses before
    // any network request, which is all these scenarios need.
    return merovingian::homeserver::perform_sync_outbound_call(runtime, "!room:remote.example.org", transaction,
                                                               "ed25519:K001", {}, "test.diagnostic", 1U);
}
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

SCENARIO("Both calls of a federated join resolve the destination once",
         "[homeserver][federation][discovery-cache][outbound]")
{
    GIVEN("a runtime whose server discovery is cached over a reachable destination")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(runtime_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto network = std::make_unique<ScriptedDiscoveryNetwork>();
        auto* const scripted = network.get();
        runtime.discovery_network = std::move(network);
        runtime.cached_discovery =
            std::make_unique<merovingian::federation::CachedServerDiscovery>(*runtime.discovery_network, 60'000U, [] {
                return 1'000U;
            });

        WHEN("make_join and send_join are sent to the same destination in turn")
        {
            auto const make_join = join_exchange_call(runtime, "/_matrix/federation/v1/make_join/!r:x/@u:y");
            auto const after_make = scripted->calls.load();
            auto const send_join = join_exchange_call(runtime, "/_matrix/federation/v2/send_join/!r:x/$e");

            THEN("the second call does not repeat the discovery cascade")
            {
                REQUIRE(after_make > 0U);
                REQUIRE(scripted->calls.load() == after_make);
                // Both got past discovery: the refusal is the missing signing secret.
                REQUIRE_FALSE(make_join.first);
                REQUIRE_FALSE(send_join.first);
                REQUIRE(make_join.second == send_join.second);
                REQUIRE(make_join.second != "server discovery failed");
            }
        }
    }
}

SCENARIO("A join retried after its destination recovers is not refused by a remembered failure",
         "[homeserver][federation][discovery-cache][outbound]")
{
    GIVEN("a runtime whose destination failed discovery on the first attempt")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = merovingian::homeserver::start_runtime(runtime_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto network = std::make_unique<ScriptedDiscoveryNetwork>();
        auto* const scripted = network.get();
        scripted->reachable = false;
        runtime.discovery_network = std::move(network);
        runtime.cached_discovery =
            std::make_unique<merovingian::federation::CachedServerDiscovery>(*runtime.discovery_network, 60'000U, [] {
                return 1'000U;
            });
        auto const failed = join_exchange_call(runtime, "/_matrix/federation/v1/make_join/!r:x/@u:y");
        REQUIRE_FALSE(failed.first);
        REQUIRE(failed.second == "server discovery failed");

        WHEN("the destination recovers and the join is retried")
        {
            scripted->reachable = true;
            auto const retried = join_exchange_call(runtime, "/_matrix/federation/v1/make_join/!r:x/@u:y");

            THEN("discovery succeeds on the retry")
            {
                REQUIRE_FALSE(retried.first);
                REQUIRE(retried.second != "server discovery failed");
            }
        }
    }
}
