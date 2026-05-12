// SPDX-License-Identifier: GPL-3.0-or-later

#include <catch2/catch_test_macros.hpp>
#include <merovingian/config/config.hpp>
#include <merovingian/homeserver/client_server.hpp>
#include <string>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.registration.enabled = true;
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
}

} // namespace

SCENARIO("Integrated client-server flow covers auth devices rooms state joined rooms sync and logout",
         "[homeserver][client-server][integration]")
{
    GIVEN("registration-enabled client-server config")
    {
        auto const config = registration_enabled_config();

        WHEN("the client-server flow is run")
        {
            auto const result = merovingian::homeserver::run_client_server_flow(config);

            THEN("the flow completes and sync returns bounded safe summaries")
            {
                REQUIRE(result.ok);
                REQUIRE(result.value.find("next_batch") != std::string::npos);
                REQUIRE(result.value.find("event_count") != std::string::npos);
                REQUIRE(result.value.find("secret") == std::string::npos);
                REQUIRE(result.value.find("m.room.encrypted") == std::string::npos);
            }
        }
    }
}

SCENARIO("Integrated client-server flow fails closed on invalid config", "[homeserver][client-server][integration]")
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

        WHEN("the client-server flow is run")
        {
            auto const result = merovingian::homeserver::run_client_server_flow(config);

            THEN("startup fails before serving API requests")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.reason == "configuration is invalid");
            }
        }
    }
}
