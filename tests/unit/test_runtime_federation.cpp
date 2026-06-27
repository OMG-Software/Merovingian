// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/config.hpp"
#include "merovingian/federation/runtime_federation.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Runtime federation config parses validated transaction limits", "[federation][runtime]")
{
    GIVEN("configuration with validated federation limits")
    {
        auto security = merovingian::config::SecurityConfig{};
        security.federation.default_policy = "deny";
        security.federation.allowed_servers = {"matrix.org"};
        security.federation.denied_servers = {"bad.example"};
        security.federation.max_transaction_size = "8MiB";
        security.federation.remote_timeout = "45s";
        auto const config = merovingian::config::Config{
            merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
            merovingian::config::DatabaseConfig{},         security,
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
        };

        WHEN("the runtime federation config is created")
        {
            auto const runtime_federation = merovingian::federation::make_runtime_federation_config(config);

            THEN("bounded runtime federation values are parsed")
            {
                REQUIRE(runtime_federation.enabled);
                REQUIRE(runtime_federation.default_policy == "deny");
                REQUIRE(runtime_federation.allowed_servers.size() == 1U);
                REQUIRE(runtime_federation.denied_servers.size() == 1U);
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
        runtime_federation.allowed_servers = {"matrix.org"};
        runtime_federation.denied_servers = {"bad.example"};
        runtime_federation.max_transaction_bytes = 10485760U;
        runtime_federation.remote_timeout_seconds = 30U;

        WHEN("the federation summary is generated")
        {
            auto const summary = merovingian::federation::federation_summary(runtime_federation);

            THEN("the expected operational values are present")
            {
                REQUIRE(summary.find("enabled=true") != std::string::npos);
                REQUIRE(summary.find("default_policy=allow") != std::string::npos);
                REQUIRE(summary.find("allowed_servers=1") != std::string::npos);
                REQUIRE(summary.find("denied_servers=1") != std::string::npos);
                REQUIRE(summary.find("max_transaction_bytes=10485760") != std::string::npos);
                REQUIRE(summary.find("remote_timeout_seconds=30") != std::string::npos);
            }
        }
    }
}

SCENARIO("Runtime federation server policy denies listed servers before default policy", "[federation][runtime]")
{
    GIVEN("an allow-by-default runtime federation config with a denied server")
    {
        auto runtime_federation = merovingian::federation::RuntimeFederationConfig{};
        runtime_federation.enabled = true;
        runtime_federation.default_policy = "allow";
        runtime_federation.denied_servers = {"bad.example"};

        WHEN("server policy is evaluated")
        {
            auto const denied = merovingian::federation::federation_server_policy(runtime_federation, "bad.example");
            auto const allowed = merovingian::federation::federation_server_policy(runtime_federation, "matrix.org");

            THEN("the deny list wins over the allow default")
            {
                REQUIRE_FALSE(denied.allowed);
                REQUIRE(denied.reason == "remote server is denied");
                REQUIRE(allowed.allowed);
            }
        }
    }
}

SCENARIO("Runtime federation server policy restricts deny-by-default federation to allowed servers",
         "[federation][runtime]")
{
    GIVEN("a deny-by-default runtime federation config with one allowed server")
    {
        auto runtime_federation = merovingian::federation::RuntimeFederationConfig{};
        runtime_federation.enabled = true;
        runtime_federation.default_policy = "deny";
        runtime_federation.allowed_servers = {"matrix.org"};
        runtime_federation.denied_servers = {"bad.example"};

        WHEN("server policy is evaluated")
        {
            auto const allowed = merovingian::federation::federation_server_policy(runtime_federation, "matrix.org");
            auto const denied_by_default =
                merovingian::federation::federation_server_policy(runtime_federation, "example.net");
            auto const denied_explicitly =
                merovingian::federation::federation_server_policy(runtime_federation, "bad.example");

            THEN("only explicitly allowed and not denied servers can federate")
            {
                REQUIRE(allowed.allowed);
                REQUIRE_FALSE(denied_by_default.allowed);
                REQUIRE(denied_by_default.reason == "remote server is not in federation allow list");
                REQUIRE_FALSE(denied_explicitly.allowed);
                REQUIRE(denied_explicitly.reason == "remote server is denied");
            }
        }
    }
}

SCENARIO("Runtime federation server policy blocks all remote servers when federation is disabled",
         "[federation][runtime]")
{
    GIVEN("a disabled runtime federation config")
    {
        auto runtime_federation = merovingian::federation::RuntimeFederationConfig{};
        runtime_federation.enabled = false;
        runtime_federation.default_policy = "allow";

        WHEN("server policy is evaluated")
        {
            auto const decision = merovingian::federation::federation_server_policy(runtime_federation, "matrix.org");

            THEN("the server is blocked")
            {
                REQUIRE_FALSE(decision.allowed);
                REQUIRE(decision.reason == "federation disabled");
            }
        }
    }
}
