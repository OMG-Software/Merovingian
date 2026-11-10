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
[[nodiscard]] auto runtime_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    return {merovingian::config::ServerConfig{},
            merovingian::config::ListenersConfig{},
            merovingian::tests::in_memory_database_config(),
            security,
            merovingian::config::ClientRateLimitsConfig{},
            merovingian::config::LogModulesConfig{}};
}

} // namespace

SCENARIO("FED-10 a runtime started for one of several worker shards resolves within its share",
         "[federation][fed10][fed10-shards]")
{
    GIVEN("the default key-resolution budgets (16 in flight, 30 per source IP)")
    {
        WHEN("a runtime starts as one of four worker shards, and another as main")
        {
            auto worker = merovingian::homeserver::start_runtime(
                merovingian::homeserver::RuntimeStartOptions{.config = runtime_config(), .key_resolution_shards = 4U});
            auto main = merovingian::homeserver::start_runtime(
                merovingian::homeserver::RuntimeStartOptions{.config = runtime_config()});

            THEN("the worker gets a quarter and main keeps the whole budget")
            {
                REQUIRE(worker.started);
                REQUIRE(main.started);
                CHECK(worker.runtime.federation.config.key_resolution_max_in_flight == 4U);
                CHECK(worker.runtime.federation.config.key_resolution_per_ip_rate.max_requests == 7U);
                CHECK(main.runtime.federation.config.key_resolution_max_in_flight == 16U);
                CHECK(main.runtime.federation.config.key_resolution_per_ip_rate.max_requests == 30U);
            }
        }
    }
}
