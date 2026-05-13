// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/reload_policy.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <string>
#include <string_view>

SCENARIO("Runtime-facing config keys are reloadable", "[config][reload]")
{
    GIVEN("runtime-facing config keys")
    {
        auto constexpr client_bind_key = "listeners.client.bind";
        auto constexpr transaction_size_key = "security.federation.max_transaction_size";
        auto constexpr federation_timeout_key = "security.federation.remote_timeout";
        auto constexpr media_timeout_key = "security.media.remote_fetch_timeout";
        auto constexpr database_pool_key = "database.pool_size";

        WHEN("their reload policies are requested")
        {
            auto const client_bind_policy = merovingian::config::reload_policy_for_key(client_bind_key);
            auto const transaction_size_policy = merovingian::config::reload_policy_for_key(transaction_size_key);
            auto const federation_timeout_policy = merovingian::config::reload_policy_for_key(federation_timeout_key);
            auto const media_timeout_policy = merovingian::config::reload_policy_for_key(media_timeout_key);
            auto const database_pool_policy = merovingian::config::reload_policy_for_key(database_pool_key);

            THEN("all policies are reloadable")
            {
                REQUIRE(client_bind_policy == merovingian::config::ReloadPolicy::reloadable);
                REQUIRE(transaction_size_policy == merovingian::config::ReloadPolicy::reloadable);
                REQUIRE(federation_timeout_policy == merovingian::config::ReloadPolicy::reloadable);
                REQUIRE(media_timeout_policy == merovingian::config::ReloadPolicy::reloadable);
                REQUIRE(database_pool_policy == merovingian::config::ReloadPolicy::reloadable);
            }
        }
    }
}

SCENARIO("Runtime-facing config groups are reloadable", "[config][reload]")
{
    GIVEN("runtime-facing config group keys")
    {
        constexpr auto keys = std::array<std::string_view, 19U>{
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
            "security.media.remote_fetch_timeout",
            "security.logging.redact_tokens",
            "security.logging.structured",
        };

        WHEN("their reload policies are checked")
        {
            auto all_reloadable = true;
            for (auto const key : keys)
            {
                all_reloadable = all_reloadable && merovingian::config::reload_policy_for_key(key) ==
                                                       merovingian::config::ReloadPolicy::reloadable;
            }

            THEN("each policy is reloadable")
            {
                REQUIRE(all_reloadable);
            }
        }
    }
}

SCENARIO("Identity and secret source config keys require restart", "[config][reload]")
{
    GIVEN("identity and secret source config keys")
    {
        auto constexpr server_name_key = "server.name";
        auto constexpr database_uri_key = "database.uri_file";
        auto constexpr tls_certificate_key = "listeners.client.tls_certificate_file";
        auto constexpr tls_private_key = "listeners.client.tls_private_key_file";

        WHEN("their reload policies are requested")
        {
            auto const server_name_policy = merovingian::config::reload_policy_for_key(server_name_key);
            auto const database_uri_policy = merovingian::config::reload_policy_for_key(database_uri_key);
            auto const tls_certificate_policy = merovingian::config::reload_policy_for_key(tls_certificate_key);
            auto const tls_private_key_policy = merovingian::config::reload_policy_for_key(tls_private_key);

            THEN("both policies require restart")
            {
                REQUIRE(server_name_policy == merovingian::config::ReloadPolicy::restart_required);
                REQUIRE(database_uri_policy == merovingian::config::ReloadPolicy::restart_required);
                REQUIRE(tls_certificate_policy == merovingian::config::ReloadPolicy::restart_required);
                REQUIRE(tls_private_key_policy == merovingian::config::ReloadPolicy::restart_required);
            }
        }
    }
}

SCENARIO("Reload policy names are stable for logs and diagnostics", "[config][reload]")
{
    GIVEN("reload policy values")
    {
        auto constexpr reloadable = merovingian::config::ReloadPolicy::reloadable;
        auto constexpr restart_required = merovingian::config::ReloadPolicy::restart_required;

        WHEN("their names are requested")
        {
            auto const reloadable_name = std::string{merovingian::config::reload_policy_name(reloadable)};
            auto const restart_required_name = std::string{merovingian::config::reload_policy_name(restart_required)};

            THEN("the diagnostic names are stable")
            {
                REQUIRE(reloadable_name == "reloadable");
                REQUIRE(restart_required_name == "restart_required");
            }
        }
    }
}
