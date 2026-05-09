// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/runtime_config.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

TEST_CASE("Runtime config snapshot reports unchanged reloads", "[config][runtime][reload]")
{
    // Given
    auto snapshot = merovingian::config::RuntimeConfigSnapshot{merovingian::config::Config{}};

    // When
    auto const result = snapshot.apply_reload(merovingian::config::Config{});

    // Then
    REQUIRE(result == merovingian::config::RuntimeConfigApplyResult::unchanged);
    REQUIRE(snapshot.current().security().federation.remote_timeout == "30s");
}

TEST_CASE("Runtime config snapshot applies reloadable changes", "[config][runtime][reload]")
{
    // Given
    auto snapshot = merovingian::config::RuntimeConfigSnapshot{merovingian::config::Config{}};
    auto security = merovingian::config::SecurityConfig{};
    security.federation.remote_timeout = "45s";
    auto const next = merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };

    // When
    auto const result = snapshot.apply_reload(next);

    // Then
    REQUIRE(result == merovingian::config::RuntimeConfigApplyResult::applied);
    REQUIRE(snapshot.current().security().federation.remote_timeout == "45s");
}

TEST_CASE("Runtime config snapshot rejects restart-required changes", "[config][runtime][reload]")
{
    // Given
    auto snapshot = merovingian::config::RuntimeConfigSnapshot{merovingian::config::Config{}};
    auto server = merovingian::config::ServerConfig{};
    server.server_name = "new.example.org";
    auto const next = merovingian::config::Config{
        server,
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        merovingian::config::SecurityConfig{},
    };

    // When
    auto const result = snapshot.apply_reload(next);

    // Then
    REQUIRE(result == merovingian::config::RuntimeConfigApplyResult::restart_required);
    REQUIRE(snapshot.current().server().server_name == "example.org");
}

TEST_CASE("Runtime config apply result names are stable", "[config][runtime][reload]")
{
    // Given / When / Then
    REQUIRE(
        std::string{merovingian::config::runtime_config_apply_result_name(
            merovingian::config::RuntimeConfigApplyResult::applied
        )}
        == "applied"
    );
    REQUIRE(
        std::string{merovingian::config::runtime_config_apply_result_name(
            merovingian::config::RuntimeConfigApplyResult::unchanged
        )}
        == "unchanged"
    );
    REQUIRE(
        std::string{merovingian::config::runtime_config_apply_result_name(
            merovingian::config::RuntimeConfigApplyResult::restart_required
        )}
        == "restart_required"
    );
}
