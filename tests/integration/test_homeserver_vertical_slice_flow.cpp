// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/local_smoke_flow.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
}

} // namespace

SCENARIO("Integrated local homeserver smoke flow boots and exercises auth room audit and logout",
         "[homeserver][vertical][integration]")
{
    GIVEN("local homeserver config with registration enabled")
    {
        auto const config = registration_enabled_config();

        WHEN("the local smoke flow is run")
        {
            auto const result = merovingian::homeserver::run_local_smoke_flow(config);

            THEN("the product path completes through runtime database auth rooms state audit and logout")
            {
                REQUIRE(result.ok);
                REQUIRE(result.value.find("room_id=!room1:example.org") != std::string::npos);
                REQUIRE(result.value.find("members=1") != std::string::npos);
                REQUIRE(result.value.find("events=1") != std::string::npos);
            }
        }
    }
}

SCENARIO("Integrated local homeserver smoke flow rejects invalid runtime config before serving",
         "[homeserver][vertical][integration]")
{
    GIVEN("an invalid listener config")
    {
        auto listeners = merovingian::config::ListenersConfig{};
        listeners.client.bind = "0.0.0.0:not-a-port";
        auto const config = merovingian::config::Config{
            merovingian::config::ServerConfig{},
            listeners,
            merovingian::config::DatabaseConfig{},
            merovingian::config::SecurityConfig{},
        };

        WHEN("the local smoke flow is run")
        {
            auto const result = merovingian::homeserver::run_local_smoke_flow(config);

            THEN("startup fails closed before any local product operation")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.reason == "configuration is invalid");
            }
        }
    }
}
