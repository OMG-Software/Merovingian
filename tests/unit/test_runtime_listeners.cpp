// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/config.hpp>
#include <merovingian/net/listener.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

TEST_CASE("Runtime listener planning includes client and federation listeners by default", "[net][listener]")
{
    // Given
    auto const config = merovingian::config::Config{};

    // When
    auto const listeners = merovingian::net::make_runtime_listeners(config);

    // Then
    REQUIRE(listeners.count() == 2U);
    REQUIRE_FALSE(listeners.empty());
    REQUIRE(listeners.plans()[0].role == merovingian::net::ListenerRole::client);
    REQUIRE(listeners.plans()[0].bind == "127.0.0.1:8008");
    REQUIRE_FALSE(listeners.plans()[0].tls);
    REQUIRE(listeners.plans()[1].role == merovingian::net::ListenerRole::federation);
    REQUIRE(listeners.plans()[1].bind == "127.0.0.1:8448");
    REQUIRE_FALSE(listeners.plans()[1].tls);
}

TEST_CASE("Runtime listener planning omits federation listener when federation is disabled", "[net][listener]")
{
    // Given
    auto security = merovingian::config::SecurityConfig{};
    security.federation.enabled = false;
    auto const config = merovingian::config::Config{
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };

    // When
    auto const listeners = merovingian::net::make_runtime_listeners(config);

    // Then
    REQUIRE(listeners.count() == 1U);
    REQUIRE(listeners.plans()[0].role == merovingian::net::ListenerRole::client);
}

TEST_CASE("Runtime listener role names are stable for logs", "[net][listener]")
{
    // Given
    auto constexpr client = merovingian::net::ListenerRole::client;
    auto constexpr federation = merovingian::net::ListenerRole::federation;

    // When
    auto const client_name = std::string{merovingian::net::listener_role_name(client)};
    auto const federation_name = std::string{merovingian::net::listener_role_name(federation)};

    // Then
    REQUIRE(client_name == "client");
    REQUIRE(federation_name == "federation");
}
