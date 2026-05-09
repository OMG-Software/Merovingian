// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/reload_plan.hpp>

#include <catch2/catch_test_macros.hpp>

TEST_CASE("Reload plan is empty for identical configs", "[config][reload]")
{
    // Given
    auto const current = merovingian::config::Config{};
    auto const next = merovingian::config::Config{};

    // When
    auto const plan = merovingian::config::build_reload_plan(current, next);

    // Then
    REQUIRE_FALSE(plan.has_changes());
    REQUIRE_FALSE(plan.has_restart_required_changes());
    REQUIRE(plan.changes.empty());
}

TEST_CASE("Reload plan marks runtime policy changes as reloadable", "[config][reload]")
{
    // Given
    auto current_security = merovingian::config::SecurityConfig{};
    auto next_security = merovingian::config::SecurityConfig{};
    next_security.federation.remote_timeout = "45s";
    next_security.federation.max_transaction_size = "8MiB";

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
    REQUIRE(plan.has_changes());
    REQUIRE_FALSE(plan.has_restart_required_changes());
    REQUIRE(plan.changes.size() == 2U);
    REQUIRE(plan.changes[0].policy == merovingian::config::ReloadPolicy::reloadable);
    REQUIRE(plan.changes[1].policy == merovingian::config::ReloadPolicy::reloadable);
}

TEST_CASE("Reload plan flags restart-required identity and secret source changes", "[config][reload]")
{
    // Given
    auto current_server = merovingian::config::ServerConfig{};
    auto next_server = merovingian::config::ServerConfig{};
    auto current_database = merovingian::config::DatabaseConfig{};
    auto next_database = merovingian::config::DatabaseConfig{};
    next_server.server_name = "new.example.org";
    next_database.uri_file = "/run/secrets/new-db-uri";

    auto const current = merovingian::config::Config{
        current_server,
        merovingian::config::ListenersConfig{},
        current_database,
        merovingian::config::SecurityConfig{},
    };
    auto const next = merovingian::config::Config{
        next_server,
        merovingian::config::ListenersConfig{},
        next_database,
        merovingian::config::SecurityConfig{},
    };

    // When
    auto const plan = merovingian::config::build_reload_plan(current, next);

    // Then
    REQUIRE(plan.has_changes());
    REQUIRE(plan.has_restart_required_changes());
    REQUIRE(plan.changes.size() == 2U);
    REQUIRE(plan.changes[0].policy == merovingian::config::ReloadPolicy::restart_required);
    REQUIRE(plan.changes[1].policy == merovingian::config::ReloadPolicy::restart_required);
}
