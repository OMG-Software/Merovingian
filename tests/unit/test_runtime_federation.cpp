// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/config.hpp>
#include <merovingian/federation/runtime_federation.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Runtime federation config parses validated transaction limits", "[federation][runtime]")
{
    GIVEN("configuration with validated federation limits")
    {
        auto security = merovingian::config::SecurityConfig{};
        security.federation.default_policy = "deny";
        security.federation.max_transaction_size = "8MiB";
        security.federation.remote_timeout = "45s";
        auto const config = merovingian::config::Config{
            merovingian::config::ServerConfig{},
            merovingian::config::ListenersConfig{},
            merovingian::config::DatabaseConfig{},
            security,
        };

        WHEN("the runtime federation config is created")
        {
            auto const runtime_federation = merovingian::federation::make_runtime_federation_config(config);

            THEN("bounded runtime federation values are parsed")
            {
                REQUIRE(runtime_federation.enabled);
                REQUIRE(runtime_federation.default_policy == "deny");
                REQUIRE(runtime_federation.require_valid_tls);
                REQUIRE(runtime_federation.verify_json_signatures);
                REQUIRE(runtime_federation.max_transaction_bytes == 8388608U);
                REQUIRE(runtime_federation.remote_timeout_seconds == 45U);
                REQUIRE(runtime_federation.deny_ip_ranges.size() == 6U);
            }
        }
    }
}

SCENARIO("Runtime federation summary exposes bounded operational values", "[federation][runtime]")
{
    GIVEN("a runtime federation config")
    {
        auto runtime_federation = merovingian::federation::RuntimeFederationConfig{};
        runtime_federation.enabled = true;
        runtime_federation.default_policy = "allow";
        runtime_federation.max_transaction_bytes = 10485760U;
        runtime_federation.remote_timeout_seconds = 30U;

        WHEN("the federation summary is generated")
        {
            auto const summary = merovingian::federation::federation_summary(runtime_federation);

            THEN("the expected operational values are present")
            {
                REQUIRE(summary.find("enabled=true") != std::string::npos);
                REQUIRE(summary.find("default_policy=allow") != std::string::npos);
                REQUIRE(summary.find("max_transaction_bytes=10485760") != std::string::npos);
                REQUIRE(summary.find("remote_timeout_seconds=30") != std::string::npos);
            }
        }
    }
}
