// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/reload_policy.hpp>

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <string>
#include <string_view>

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

TEST_CASE("Runtime-facing config groups are reloadable", "[config][reload]")
{
    // Given
    constexpr auto keys = std::array<std::string_view, 18U>{
        "server.public_baseurl",
        "server.trusted_proxies",
        "listeners.client.bind",
        "listeners.client.tls",
        "listeners.federation.bind",
        "listeners.federation.tls",
        "database.pool_size",
        "security.registration.enabled",
        "security.registration.require_token",
        "security.encryption.default_for_new_rooms",
        "security.encryption.require_for_direct_messages",
        "security.federation.enabled",
        "security.federation.default_policy",
        "security.federation.max_transaction_size",
        "security.federation.remote_timeout",
        "security.media.max_upload_size",
        "security.logging.redact_tokens",
        "security.logging.structured",
    };

    // When / Then
    for (auto const key : keys)
    {
        REQUIRE(merovingian::config::reload_policy_for_key(key) == merovingian::config::ReloadPolicy::reloadable);
    }
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
