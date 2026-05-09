// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/runtime_config.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Runtime config snapshot reports unchanged reloads", "[config][runtime][reload]")
{
    GIVEN("a runtime config snapshot with default config")
    {
        auto snapshot = merovingian::config::RuntimeConfigSnapshot{merovingian::config::Config{}};

        WHEN("the same config is applied")
        {
            auto const result = snapshot.apply_reload(merovingian::config::Config{});

            THEN("the reload is reported as unchanged")
            {
                REQUIRE(result == merovingian::config::RuntimeConfigApplyResult::unchanged);
                REQUIRE(snapshot.current().security().federation.remote_timeout == "30s");
            }
        }
    }
}

SCENARIO("Runtime config snapshot applies reloadable changes", "[config][runtime][reload]")
{
    GIVEN("a runtime config snapshot and a reloadable next config")
    {
        auto snapshot = merovingian::config::RuntimeConfigSnapshot{merovingian::config::Config{}};
        auto security = merovingian::config::SecurityConfig{};
        security.federation.remote_timeout = "45s";
        auto const next = merovingian::config::Config{
            merovingian::config::ServerConfig{},
            merovingian::config::ListenersConfig{},
            merovingian::config::DatabaseConfig{},
            security,
        };

        WHEN("the next config is applied")
        {
            auto const result = snapshot.apply_reload(next);

            THEN("the snapshot updates in place")
            {
                REQUIRE(result == merovingian::config::RuntimeConfigApplyResult::applied);
                REQUIRE(snapshot.current().security().federation.remote_timeout == "45s");
            }
        }
    }
}

SCENARIO("Runtime config snapshot rejects restart-required changes", "[config][runtime][reload]")
{
    GIVEN("a runtime config snapshot and a restart-required next config")
    {
        auto snapshot = merovingian::config::RuntimeConfigSnapshot{merovingian::config::Config{}};
        auto server = merovingian::config::ServerConfig{};
        server.server_name = "new.example.org";
        auto const next = merovingian::config::Config{
            server,
            merovingian::config::ListenersConfig{},
            merovingian::config::DatabaseConfig{},
            merovingian::config::SecurityConfig{},
        };

        WHEN("the next config is applied")
        {
            auto const result = snapshot.apply_reload(next);

            THEN("the snapshot keeps the current config")
            {
                REQUIRE(result == merovingian::config::RuntimeConfigApplyResult::restart_required);
                REQUIRE(snapshot.current().server().server_name == "example.org");
            }
        }
    }
}

SCENARIO("Runtime config apply result names are stable", "[config][runtime][reload]")
{
    GIVEN("runtime config apply result values")
    {
        auto constexpr applied = merovingian::config::RuntimeConfigApplyResult::applied;
        auto constexpr unchanged = merovingian::config::RuntimeConfigApplyResult::unchanged;
        auto constexpr restart_required = merovingian::config::RuntimeConfigApplyResult::restart_required;

        WHEN("their names are requested")
        {
            auto const applied_name = std::string{merovingian::config::runtime_config_apply_result_name(applied)};
            auto const unchanged_name = std::string{merovingian::config::runtime_config_apply_result_name(unchanged)};
            auto const restart_required_name = std::string{merovingian::config::runtime_config_apply_result_name(restart_required)};

            THEN("the diagnostic names are stable")
            {
                REQUIRE(applied_name == "applied");
                REQUIRE(unchanged_name == "unchanged");
                REQUIRE(restart_required_name == "restart_required");
            }
        }
    }
}
