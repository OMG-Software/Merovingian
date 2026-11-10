// SPDX-License-Identifier: GPL-3.0-or-later

// FED-10 (29 Sep 2026 audit): network key resolution is admitted against a
// process-wide in-flight cap and a per-source-IP rate. Each federation worker
// shard is its own process, so N shards used to allow N times both budgets.
// A worker now gets its shard's share (ADR-0153).

#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/federation/RuntimeFederationConfig.hpp"
#include "merovingian/homeserver/HomeserverRuntime.hpp"
#include "merovingian/homeserver/RuntimeStartOptions.hpp"
#include "merovingian/homeserver/RuntimeStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>

namespace
{

[[nodiscard]] auto budget(std::uint32_t in_flight, std::uint32_t per_ip)
    -> merovingian::federation::RuntimeFederationConfig
{
    auto config = merovingian::federation::RuntimeFederationConfig{};
    config.key_resolution_max_in_flight = in_flight;
    config.key_resolution_per_ip_rate = {per_ip, 60U};
    return config;
}

} // namespace

SCENARIO("FED-10 a worker shard's key-resolution budgets are its share of the configured ones",
         "[federation][fed10][fed10-shards]")
{
    GIVEN("budgets of 16 resolutions in flight and 30 per source IP per minute")
    {
        WHEN("they are split across four shards")
        {
            auto const share = merovingian::federation::shard_key_resolution_budget(budget(16U, 30U), 4U);

            THEN("each shard gets a quarter, rounded down, so the four together stay within the limits")
            {
                CHECK(share.key_resolution_max_in_flight == 4U);
                CHECK(share.key_resolution_per_ip_rate.max_requests == 7U);
                CHECK(share.key_resolution_per_ip_rate.window_seconds == 60U);
            }
        }

        WHEN("they are split across more shards than the limit")
        {
            auto const share = merovingian::federation::shard_key_resolution_budget(budget(16U, 30U), 64U);

            THEN("each shard still gets one, so no shard is unable to resolve at all")
            {
                CHECK(share.key_resolution_max_in_flight == 1U);
                CHECK(share.key_resolution_per_ip_rate.max_requests == 1U);
            }
        }

        WHEN("there is one shard")
        {
            auto const share = merovingian::federation::shard_key_resolution_budget(budget(16U, 30U), 1U);

            THEN("it gets the whole budget")
            {
                CHECK(share.key_resolution_max_in_flight == 16U);
                CHECK(share.key_resolution_per_ip_rate.max_requests == 30U);
            }
        }
    }
}

SCENARIO("FED-10 one transaction's sender-key pre-pass never asks for more admissions than its runtime's cap",
         "[federation][fed10][fed10-shards]")
{
    // PR #509 review: admission refuses work over the in-flight cap rather than
    // queueing it. With four shards the cap is 4, but the pre-pass ran
    // join_parallelism (default 8) resolutions at once, so any transaction with
    // five or more cold sender servers always got a 503 from its own fan-out.
    GIVEN("a pre-pass parallelism and an in-flight cap")
    {
        auto const parallelism = [](std::uint32_t join_parallelism, std::uint32_t in_flight) {
            auto config = budget(in_flight, 30U);
            config.join_parallelism = join_parallelism;
            return merovingian::federation::sender_key_prepass_parallelism(config);
        };

        WHEN("the parallelism is computed for shard-sized and whole budgets")
        {
            THEN("it is the configured parallelism, bounded by the in-flight cap, 64, and at least 1")
            {
                CHECK(parallelism(8U, 4U) == 4U);
                CHECK(parallelism(8U, 1U) == 1U);
                CHECK(parallelism(8U, 16U) == 8U);
                CHECK(parallelism(100U, 1000U) == 64U);
                CHECK(parallelism(0U, 16U) == 1U);
                CHECK(parallelism(8U, 0U) == 1U);
            }
        }
    }
}
