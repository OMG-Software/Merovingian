// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/config.hpp"
#include "merovingian/config/config_parser.hpp"
#include "merovingian/config/reload_plan.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Media remote fetch timeout has a bounded secure default", "[config][media]")
{
    GIVEN("the default configuration")
    {
        auto const config = merovingian::config::Config{};

        WHEN("the media remote fetch timeout is parsed")
        {
            auto const parsed =
                merovingian::config::parse_duration_seconds(config.security().media.remote_fetch_timeout);

            THEN("the timeout is bounded and valid")
            {
                REQUIRE(config.security().media.remote_fetch_timeout == "30s");
                REQUIRE(parsed.valid);
                REQUIRE(parsed.seconds == 30U);
            }
        }
    }
}

SCENARIO("Media remote fetch timeout is parsed from key-value config", "[config][media][parser]")
{
    GIVEN("key-value configuration containing a media timeout")
    {
        auto const input = std::string{"security.media.remote_fetch_timeout=45s\n"};

        WHEN("the config is parsed")
        {
            auto const result = merovingian::config::parse_key_value_config(input);

            THEN("the media timeout is applied")
            {
                REQUIRE(result.findings.empty());
                REQUIRE(result.config.security().media.remote_fetch_timeout == "45s");
            }
        }
    }
}

SCENARIO("Media remote fetch timeout rejects invalid values", "[config][media][validation]")
{
    GIVEN("configuration with an invalid media timeout")
    {
        auto security = merovingian::config::SecurityConfig{};
        security.media.remote_fetch_timeout = "bad-duration";
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

SCENARIO("Media remote fetch timeout changes are reloadable", "[config][media][reload]")
{
    GIVEN("current and next configs with different media timeouts")
    {
        auto current_security = merovingian::config::SecurityConfig{};
        auto next_security = merovingian::config::SecurityConfig{};
        current_security.media.remote_fetch_timeout = "30s";
        next_security.media.remote_fetch_timeout = "45s";

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

            THEN("the timeout change is marked reloadable")
            {
                REQUIRE(plan.changes().size() == 1U);
                REQUIRE(plan.changes()[0].key == "security.media.remote_fetch_timeout");
                REQUIRE(plan.changes()[0].policy == merovingian::config::ReloadPolicy::reloadable);
            }
        }
    }
}
