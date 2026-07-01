// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/config.hpp"
#include "merovingian/config/config_parser.hpp"
#include "merovingian/config/reload_plan.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Federation join timeout and parallelism have secure defaults", "[config][federation][join]")
{
    GIVEN("the default configuration")
    {
        auto const config = merovingian::config::Config{};

        WHEN("the join timeout and parallelism are parsed")
        {
            auto const join_timeout =
                merovingian::config::parse_duration_seconds(config.security().federation.join_timeout);

            THEN("the defaults are bounded and valid")
            {
                REQUIRE(config.security().federation.join_timeout == "180s");
                REQUIRE(join_timeout.valid);
                REQUIRE(join_timeout.seconds == 180U);
                REQUIRE(config.security().federation.join_parallelism == 8U);
            }
        }
    }
}

SCENARIO("Federation join timeout and parallelism are parsed from key-value config",
         "[config][federation][join][parser]")
{
    GIVEN("key-value configuration containing join timeout and parallelism")
    {
        auto const input = std::string{"security.federation.join_timeout=240s\n"
                                       "security.federation.join_parallelism=16\n"};

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("both values are applied")
            {
                REQUIRE(result.findings.empty());
                REQUIRE(result.config.security().federation.join_timeout == "240s");
                REQUIRE(result.config.security().federation.join_parallelism == 16U);
            }
        }
    }
}

SCENARIO("Federation join timeout rejects invalid durations", "[config][federation][join][validation]")
{
    GIVEN("configuration with an invalid join timeout")
    {
        auto security = merovingian::config::SecurityConfig{};
        security.federation.join_timeout = "bad-duration";
        auto const config = merovingian::config::Config{
            merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
            merovingian::config::DatabaseConfig{},         security,
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
        };

        WHEN("the config is validated")
        {
            auto const findings = merovingian::config::validate(config);
            auto const valid = merovingian::config::is_valid(config);

            THEN("validation fails")
            {
                REQUIRE_FALSE(findings.empty());
                REQUIRE_FALSE(valid);
            }
        }
    }
}

SCENARIO("Federation join parallelism rejects zero", "[config][federation][join][validation]")
{
    GIVEN("configuration with zero join parallelism")
    {
        auto security = merovingian::config::SecurityConfig{};
        security.federation.join_parallelism = 0U;
        auto const config = merovingian::config::Config{
            merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
            merovingian::config::DatabaseConfig{},         security,
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
        };

        WHEN("the config is validated")
        {
            auto const findings = merovingian::config::validate(config);
            auto const valid = merovingian::config::is_valid(config);

            THEN("validation fails")
            {
                REQUIRE_FALSE(findings.empty());
                REQUIRE_FALSE(valid);
            }
        }
    }
}

SCENARIO("Federation join timeout changes are reloadable", "[config][federation][join][reload]")
{
    GIVEN("current and next configs with different join timeouts")
    {
        auto current_security = merovingian::config::SecurityConfig{};
        auto next_security = merovingian::config::SecurityConfig{};
        current_security.federation.join_timeout = "180s";
        next_security.federation.join_timeout = "240s";

        auto const current = merovingian::config::Config{
            merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
            merovingian::config::DatabaseConfig{},         current_security,
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
        };
        auto const next = merovingian::config::Config{
            merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
            merovingian::config::DatabaseConfig{},         next_security,
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
        };

        WHEN("a reload plan is built")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("the join timeout change is marked reloadable")
            {
                REQUIRE(plan.changes().size() == 1U);
                REQUIRE(plan.changes()[0].key == "security.federation.join_timeout");
                REQUIRE(plan.changes()[0].policy == merovingian::config::ReloadPolicy::reloadable);
            }
        }
    }
}

SCENARIO("Federation join parallelism changes are reloadable", "[config][federation][join][reload]")
{
    GIVEN("current and next configs with different join parallelism")
    {
        auto current_security = merovingian::config::SecurityConfig{};
        auto next_security = merovingian::config::SecurityConfig{};
        current_security.federation.join_parallelism = 8U;
        next_security.federation.join_parallelism = 16U;

        auto const current = merovingian::config::Config{
            merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
            merovingian::config::DatabaseConfig{},         current_security,
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
        };
        auto const next = merovingian::config::Config{
            merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
            merovingian::config::DatabaseConfig{},         next_security,
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
        };

        WHEN("a reload plan is built")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("the join parallelism change is marked reloadable")
            {
                REQUIRE(plan.changes().size() == 1U);
                REQUIRE(plan.changes()[0].key == "security.federation.join_parallelism");
                REQUIRE(plan.changes()[0].policy == merovingian::config::ReloadPolicy::reloadable);
            }
        }
    }
}