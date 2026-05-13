// SPDX-License-Identifier: GPL-3.0-or-later

#include <string>

#include <catch2/catch_test_macros.hpp>
#include "merovingian/config/config.hpp"
#include "merovingian/net/listener.hpp"

SCENARIO("Runtime listener planning includes client and federation listeners by default", "[net][listener]")
{
    GIVEN("the default configuration")
    {
        auto const config = merovingian::config::Config{};

        WHEN("runtime listeners are planned")
        {
            auto const listeners = merovingian::net::make_runtime_listeners(config);

            THEN("client and federation listeners are included")
            {
                REQUIRE(listeners.count() == 2U);
                REQUIRE_FALSE(listeners.empty());
                REQUIRE(listeners.plans()[0].role == merovingian::net::ListenerRole::client);
                REQUIRE(listeners.plans()[0].bind == "127.0.0.1:8008");
                REQUIRE_FALSE(listeners.plans()[0].tls);
                REQUIRE(listeners.plans()[0].tls_certificate_file.empty());
                REQUIRE(listeners.plans()[0].tls_private_key_file.empty());
                REQUIRE(listeners.plans()[1].role == merovingian::net::ListenerRole::federation);
                REQUIRE(listeners.plans()[1].bind == "127.0.0.1:8448");
                REQUIRE_FALSE(listeners.plans()[1].tls);
            }
        }
    }
}

SCENARIO("Runtime listener planning carries TLS certificate paths", "[net][listener][tls]")
{
    GIVEN("configuration with TLS enabled for both runtime listeners")
    {
        auto listeners_config = merovingian::config::ListenersConfig{};
        listeners_config.client.tls = true;
        listeners_config.client.tls_certificate_file = "/etc/merovingian/client.pem";
        listeners_config.client.tls_private_key_file = "/etc/merovingian/client.key";
        listeners_config.federation.tls = true;
        listeners_config.federation.tls_certificate_file = "/etc/merovingian/federation.pem";
        listeners_config.federation.tls_private_key_file = "/etc/merovingian/federation.key";
        auto const config = merovingian::config::Config{
            merovingian::config::ServerConfig{},
            listeners_config,
            merovingian::config::DatabaseConfig{},
            merovingian::config::SecurityConfig{},
        };

        WHEN("runtime listeners are planned")
        {
            auto const listeners = merovingian::net::make_runtime_listeners(config);

            THEN("the TLS key material paths are retained for listener startup")
            {
                REQUIRE(listeners.count() == 2U);
                REQUIRE(listeners.plans()[0].tls);
                REQUIRE(listeners.plans()[0].tls_certificate_file == "/etc/merovingian/client.pem");
                REQUIRE(listeners.plans()[0].tls_private_key_file == "/etc/merovingian/client.key");
                REQUIRE(listeners.plans()[1].tls);
                REQUIRE(listeners.plans()[1].tls_certificate_file == "/etc/merovingian/federation.pem");
                REQUIRE(listeners.plans()[1].tls_private_key_file == "/etc/merovingian/federation.key");
            }
        }
    }
}

SCENARIO("Runtime listener planning omits federation listener when federation is disabled", "[net][listener]")
{
    GIVEN("configuration with federation disabled")
    {
        auto security = merovingian::config::SecurityConfig{};
        security.federation.enabled = false;
        auto const config = merovingian::config::Config{
            merovingian::config::ServerConfig{},
            merovingian::config::ListenersConfig{},
            merovingian::config::DatabaseConfig{},
            security,
        };

        WHEN("runtime listeners are planned")
        {
            auto const listeners = merovingian::net::make_runtime_listeners(config);

            THEN("only the client listener is included")
            {
                REQUIRE(listeners.count() == 1U);
                REQUIRE(listeners.plans()[0].role == merovingian::net::ListenerRole::client);
            }
        }
    }
}

SCENARIO("Runtime listener role names are stable for logs", "[net][listener]")
{
    GIVEN("listener roles")
    {
        auto constexpr client = merovingian::net::ListenerRole::client;
        auto constexpr federation = merovingian::net::ListenerRole::federation;

        WHEN("their names are requested")
        {
            auto const client_name = std::string{merovingian::net::listener_role_name(client)};
            auto const federation_name = std::string{merovingian::net::listener_role_name(federation)};

            THEN("the diagnostic names are stable")
            {
                REQUIRE(client_name == "client");
                REQUIRE(federation_name == "federation");
            }
        }
    }
}
