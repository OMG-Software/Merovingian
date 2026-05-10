// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/config.hpp>
#include <merovingian/homeserver/vertical_slice.hpp>

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("Integrated homeserver vertical slice boots and exercises local auth room audit and logout", "[homeserver][vertical][integration]")
{
    GIVEN("the default local homeserver config")
    {
        auto const config = merovingian::config::Config{};

        WHEN("the local vertical slice is run")
        {
            auto const result = merovingian::homeserver::run_local_vertical_slice(config);

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

SCENARIO("Integrated homeserver vertical slice rejects invalid runtime config before serving", "[homeserver][vertical][integration]")
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

        WHEN("the local vertical slice is run")
        {
            auto const result = merovingian::homeserver::run_local_vertical_slice(config);

            THEN("startup fails closed before any local product operation")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.reason == "configuration is invalid");
            }
        }
    }
}
