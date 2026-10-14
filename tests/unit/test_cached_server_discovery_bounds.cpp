// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation/cached_server_discovery.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <barrier>
#include <cstdint>
#include <string>
#include <thread>
#include <tuple>
#include <vector>

namespace
{
class BoundsDiscoveryNetwork final : public merovingian::federation::ServerDiscoveryNetwork
{
public:
    std::atomic<std::uint64_t> calls{0U};
    bool ok{true};

    [[nodiscard]] auto fetch_well_known(std::string_view,
                                        std::uint32_t) -> merovingian::federation::WellKnownServerResult override
    {
        return {};
    }
    [[nodiscard]] auto lookup_srv(std::string_view) -> std::vector<merovingian::federation::SrvRecord> override
    {
        return {};
    }
    [[nodiscard]] auto lookup_addresses(std::string_view,
                                        std::uint16_t) -> merovingian::federation::ResolvedAddressSet override
    {
        ++calls;
        return {ok, ok ? std::vector<std::string>{"203.0.113.10"} : std::vector<std::string>{}, "unreachable"};
    }
};
} // namespace

SCENARIO("server discovery expires unrelated entries before serving a cache hit", "[federation][out-6]")
{
    GIVEN("two entries fetched at different times with a ten millisecond TTL")
    {
        auto network = BoundsDiscoveryNetwork{};
        auto now = std::uint64_t{100U};
        auto cached = merovingian::federation::CachedServerDiscovery{network, 10U,
                                                                     [&now] {
                                                                         return now;
                                                                     },
                                                                     3U};
        REQUIRE(cached.discover("old.example:8448", 1U).discovery_allowed);
        now = 105U;
        REQUIRE(cached.discover("fresh.example:8448", 1U).discovery_allowed);
        WHEN("a fresh entry is hit exactly when the other entry expires")
        {
            now = 110U;
            auto const calls = network.calls.load();
            auto const result = cached.discover("fresh.example:8448", 1U);
            THEN("the expired entry is removed without refetching the fresh entry")
            {
                REQUIRE(result.discovery_allowed);
                REQUIRE(network.calls.load() == calls);
                REQUIRE(cached.size() == 1U);
            }
        }
    }
}

SCENARIO("invalid server names never consume discovery cache entries", "[federation][out-6]")
{
    GIVEN("an empty cache with capacity three")
    {
        auto network = BoundsDiscoveryNetwork{};
        auto cached = merovingian::federation::CachedServerDiscovery{network, 100U,
                                                                     [] {
                                                                         return 1U;
                                                                     },
                                                                     3U};
        WHEN("names with invalid authorities are discovered")
        {
            auto const invalid = std::vector<std::string>{"bad@example.org", "example.org#fragment", "example.org?x",
                                                          "", "example.org:99999"};
            for (auto const& name : invalid)
            {
                REQUIRE_FALSE(cached.discover(name, 1U).discovery_allowed);
            }
            THEN("no network work or cache admission occurs")
            {
                REQUIRE(network.calls.load() == 0U);
                REQUIRE(cached.size() == 0U);
            }
        }
    }
}

SCENARIO("server discovery obeys custom and disabled cache capacities", "[federation][out-6]")
{
    GIVEN("a cache capacity of two")
    {
        auto network = BoundsDiscoveryNetwork{};
        auto cached = merovingian::federation::CachedServerDiscovery{network, 100U,
                                                                     [] {
                                                                         return 1U;
                                                                     },
                                                                     2U};
        WHEN("three distinct valid names are discovered")
        {
            for (auto index = 0U; index < 3U; ++index)
            {
                REQUIRE(cached.discover("server" + std::to_string(index) + ".example:8448", 1U).discovery_allowed);
            }
            THEN("the configured capacity is never exceeded")
            {
                REQUIRE(cached.size() == 2U);
            }
        }
    }
    GIVEN("caching is disabled")
    {
        auto network = BoundsDiscoveryNetwork{};
        auto cached = merovingian::federation::CachedServerDiscovery{network, 100U,
                                                                     [] {
                                                                         return 1U;
                                                                     },
                                                                     0U};
        WHEN("the same valid name is discovered twice")
        {
            REQUIRE(cached.discover("server.example:8448", 1U).discovery_allowed);
            REQUIRE(cached.discover("server.example:8448", 1U).discovery_allowed);
            THEN("both requests reach the network and no entry is retained")
            {
                REQUIRE(network.calls.load() == 2U);
                REQUIRE(cached.size() == 0U);
            }
        }
    }
}

SCENARIO("concurrent discovery admissions cannot exceed the cache capacity", "[federation][out-6]")
{
    GIVEN("sixteen callers released together and a capacity of three")
    {
        auto network = BoundsDiscoveryNetwork{};
        auto cached = merovingian::federation::CachedServerDiscovery{network, 100U,
                                                                     [] {
                                                                         return 1U;
                                                                     },
                                                                     3U};
        auto start = std::barrier{16};
        auto all_allowed = std::atomic<bool>{true};
        auto callers = std::vector<std::jthread>{};
        WHEN("each caller discovers its own name")
        {
            for (auto index = 0U; index < 16U; ++index)
            {
                callers.emplace_back([&, index] {
                    start.arrive_and_wait();
                    if (!cached.discover("server" + std::to_string(index) + ".example:8448", 1U).discovery_allowed ||
                        cached.size() > 3U)
                    {
                        all_allowed.store(false);
                    }
                });
            }
            callers.clear();
            THEN("every discovery succeeds within the shared capacity")
            {
                REQUIRE(all_allowed.load());
                REQUIRE(cached.size() == 3U);
            }
        }
    }
}

SCENARIO("server discovery has a finite default entry cap", "[federation][out-6][cache-cap]")
{
    GIVEN("1025 distinct valid names discovered within one TTL")
    {
        auto network = BoundsDiscoveryNetwork{};
        auto cached = merovingian::federation::CachedServerDiscovery{network, 60000U, [] {
                                                                         return 1000U;
                                                                     }};
        for (auto index = 0U; index < 1025U; ++index)
        {
            REQUIRE(cached.discover("server" + std::to_string(index) + ".example:8448", 1U).discovery_allowed);
        }
        WHEN("each name is looked up again")
        {
            for (auto index = 0U; index < 1025U; ++index)
            {
                std::ignore = cached.discover("server" + std::to_string(index) + ".example:8448", 1U);
            }
            THEN("at least one name was evicted instead of retaining all 1025 entries")
            {
                REQUIRE(network.calls.load() > 1025U);
            }
        }
    }
}
