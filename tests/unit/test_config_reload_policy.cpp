// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/reload_policy.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

TEST_CASE("Runtime-facing config keys are reloadable", "[config][reload]")
{
    // Given / When / Then
    REQUIRE(
        merovingian::config::reload_policy_for_key("listeners.client.bind")
        == merovingian::config::ReloadPolicy::reloadable
    );
    REQUIRE(
        merovingian::config::reload_policy_for_key("security.federation.max_transaction_size")
        == merovingian::config::ReloadPolicy::reloadable
    );
    REQUIRE(
        merovingian::config::reload_policy_for_key("security.federation.remote_timeout")
        == merovingian::config::ReloadPolicy::reloadable
    );
    REQUIRE(
        merovingian::config::reload_policy_for_key("database.pool_size")
        == merovingian::config::ReloadPolicy::reloadable
    );
}

TEST_CASE("Identity and secret source config keys require restart", "[config][reload]")
{
    // Given / When / Then
    REQUIRE(
        merovingian::config::reload_policy_for_key("server.name")
        == merovingian::config::ReloadPolicy::restart_required
    );
    REQUIRE(
        merovingian::config::reload_policy_for_key("database.uri_file")
        == merovingian::config::ReloadPolicy::restart_required
    );
}

TEST_CASE("Reload policy names are stable for logs and diagnostics", "[config][reload]")
{
    // Given / When / Then
    REQUIRE(
        std::string{merovingian::config::reload_policy_name(merovingian::config::ReloadPolicy::reloadable)}
        == "reloadable"
    );
    REQUIRE(
        std::string{merovingian::config::reload_policy_name(merovingian::config::ReloadPolicy::restart_required)}
        == "restart_required"
    );
}
