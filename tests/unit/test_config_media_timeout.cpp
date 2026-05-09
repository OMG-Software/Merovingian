// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/config.hpp>
#include <merovingian/config/config_parser.hpp>
#include <merovingian/config/reload_plan.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

TEST_CASE("Media remote fetch timeout has a bounded secure default", "[config][media]")
{
    // Given
    auto const config = merovingian::config::Config{};

    // When
    auto const parsed = merovingian::config::parse_duration_seconds(config.security().media.remote_fetch_timeout);

    // Then
    REQUIRE(config.security().media.remote_fetch_timeout == "30s");
    REQUIRE(parsed.valid);
    REQUIRE(parsed.seconds == 30U);
}

TEST_CASE("Media remote fetch timeout is parsed from key-value config", "[config][media][parser]")
{
    // Given
    auto const input = std::string{"security.media.remote_fetch_timeout=45s\n"};

    // When
    auto const result = merovingian::config::parse_key_value_config(input);

    // Then
    REQUIRE(result.findings.empty());
    REQUIRE(result.config.security().media.remote_fetch_timeout == "45s");
}

TEST_CASE("Media remote fetch timeout rejects invalid values", "[config][media][validation]")
{
    // Given
    auto security = merovingian::config::SecurityConfig{};
    security.media.remote_fetch_timeout = "bad-duration";
    auto const config = merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };

    // When
    auto const findings = merovingian::config::validate(config);
    auto const valid = merovingian::config::is_valid(config);

    // Then
    REQUIRE_FALSE(findings.empty());
    REQUIRE_FALSE(valid);
}

TEST_CASE("Media remote fetch timeout changes are reloadable", "[config][media][reload]")
{
    // Given
    auto current_security = merovingian::config::SecurityConfig{};
    auto next_security = merovingian::config::SecurityConfig{};
    current_security.media.remote_fetch_timeout = "30s";
    next_security.media.remote_fetch_timeout = "45s";

    auto const current = merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        current_security,
    };
    auto const next = merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        next_security,
    };

    // When
    auto const plan = merovingian::config::build_reload_plan(current, next);

    // Then
    REQUIRE(plan.changes().size() == 1U);
    REQUIRE(plan.changes()[0].key == "security.media.remote_fetch_timeout");
    REQUIRE(plan.changes()[0].policy == merovingian::config::ReloadPolicy::reloadable);
}
