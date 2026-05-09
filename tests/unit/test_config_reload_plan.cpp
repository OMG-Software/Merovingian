// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/reload_plan.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Reload plan is empty for identical configs", "[config][reload]")
{
    GIVEN("identical current and next configs")
    {
        auto const current = merovingian::config::Config{};
        auto const next = merovingian::config::Config{};

        WHEN("a reload plan is built")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("the plan reports no changes")
            {
                REQUIRE_FALSE(plan.has_changes());
                REQUIRE_FALSE(plan.has_restart_required_changes());
                REQUIRE(plan.reloadable_change_count() == 0U);
                REQUIRE(plan.restart_required_change_count() == 0U);
                REQUIRE(plan.changes().empty());
                REQUIRE(merovingian::config::reload_plan_summary(plan) == "Reload plan: changes=0 reloadable=0 restart_required=0");
            }
        }
    }
}

SCENARIO("Reload plan marks runtime policy changes as reloadable", "[config][reload]")
{
    GIVEN("current and next configs with runtime policy changes")
    {
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

        WHEN("a reload plan is built")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("the changes are reloadable")
            {
                REQUIRE(plan.has_changes());
                REQUIRE_FALSE(plan.has_restart_required_changes());
                REQUIRE(plan.changes().size() == 2U);
                REQUIRE(plan.reloadable_change_count() == 2U);
                REQUIRE(plan.restart_required_change_count() == 0U);
                REQUIRE(plan.changes()[0].policy == merovingian::config::ReloadPolicy::reloadable);
                REQUIRE(plan.changes()[1].policy == merovingian::config::ReloadPolicy::reloadable);
                REQUIRE(merovingian::config::reload_plan_summary(plan) == "Reload plan: changes=2 reloadable=2 restart_required=0");
            }
        }
    }
}

SCENARIO("Reload plan flags restart-required identity and secret source changes", "[config][reload]")
{
    GIVEN("current and next configs with identity and secret source changes")
    {
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

        WHEN("a reload plan is built")
        {
            auto const plan = merovingian::config::build_reload_plan(current, next);

            THEN("the changes require restart")
            {
                REQUIRE(plan.has_changes());
                REQUIRE(plan.has_restart_required_changes());
                REQUIRE(plan.changes().size() == 2U);
                REQUIRE(plan.reloadable_change_count() == 0U);
                REQUIRE(plan.restart_required_change_count() == 2U);
                REQUIRE(plan.changes()[0].policy == merovingian::config::ReloadPolicy::restart_required);
                REQUIRE(plan.changes()[1].policy == merovingian::config::ReloadPolicy::restart_required);
                REQUIRE(merovingian::config::reload_plan_summary(plan) == "Reload plan: changes=2 reloadable=0 restart_required=2");
            }
        }
    }
}
