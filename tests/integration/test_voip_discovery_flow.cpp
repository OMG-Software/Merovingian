// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Voice and video call discovery at request level: several TURN URIs in GET /voip/turnServer (ADR-0821) and the
// MatrixRTC transports (MSC4143, ADR-0822). The transports routes are not in the Matrix v1.19 specification, so they
// have no conformance scenario.

#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <string>
#include <variant>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto voip_config(merovingian::config::ServerConfig server) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        std::move(server),
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        std::move(security),
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto login(merovingian::homeserver::ClientServerRuntime& runtime) -> std::string
{
    REQUIRE(merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                .response.status == 200U);
    auto const response = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/login",
                  {},
                  R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},)"
                  R"("password":"CorrectHorse7!","device_id":"D1"})"});
    REQUIRE(response.response.status == 200U);
    auto const body = parse_object(response.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto text_at(merovingian::canonicaljson::Array const& array, std::size_t index) -> std::string
{
    auto const* text = std::get_if<std::string>(&array.at(index).storage());
    return text == nullptr ? std::string{"<not a string>"} : *text;
}

[[nodiscard]] auto get(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& target,
                       std::string const& token = {}) -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(runtime, {"GET", target, token, {}}).response;
}

} // namespace

SCENARIO("GET /voip/turnServer returns every server.turn.uris entry in order with static credentials",
         "[homeserver][turn][turn-uris][client-server]")
{
    GIVEN("a server with three TURN URIs and static credentials")
    {
        auto server = merovingian::config::ServerConfig{};
        server.turn.uris = {"turn:turn.example.org:3478?transport=udp", "turn:turn.example.org:3478?transport=tcp",
                            "turns:turn.example.org:5349?transport=tcp"};
        server.turn.username = "turnuser";
        server.turn.password = "turnpass";
        server.turn.ttl_seconds = 600U;
        auto started = merovingian::homeserver::start_client_server(voip_config(std::move(server)));
        REQUIRE(started.started);
        auto const token = login(started.runtime);

        WHEN("a client asks for TURN credentials")
        {
            auto const response = get(started.runtime, "/_matrix/client/v3/voip/turnServer", token);

            THEN("the uris array holds the three entries in the configured order")
            {
                REQUIRE(response.status == 200U);
                auto const body = parse_object(response.body);
                REQUIRE(string_member(body, "username") != nullptr);
                CHECK(*string_member(body, "username") == "turnuser");
                CHECK(*string_member(body, "password") == "turnpass");
                CHECK(*int_member(body, "ttl") == 600);
                auto const* uris = object_member_as_array(body, "uris");
                REQUIRE(uris != nullptr);
                REQUIRE(uris->size() == 3U);
                CHECK(text_at(*uris, 0U) == "turn:turn.example.org:3478?transport=udp");
                CHECK(text_at(*uris, 1U) == "turn:turn.example.org:3478?transport=tcp");
                CHECK(text_at(*uris, 2U) == "turns:turn.example.org:5349?transport=tcp");
            }
        }
    }

    GIVEN("a server configured the 1.0.x way with the single server.turn.server")
    {
        auto server = merovingian::config::ServerConfig{};
        server.turn.server = "turn:turn.example.org:3478";
        server.turn.username = "turnuser";
        server.turn.password = "turnpass";
        auto started = merovingian::homeserver::start_client_server(voip_config(std::move(server)));
        REQUIRE(started.started);
        auto const token = login(started.runtime);

        WHEN("a client asks for TURN credentials")
        {
            auto const response = get(started.runtime, "/_matrix/client/v3/voip/turnServer", token);

            THEN("uris holds that one entry, as before")
            {
                REQUIRE(response.status == 200U);
                auto const body = parse_object(response.body);
                auto const* uris = object_member_as_array(body, "uris");
                REQUIRE(uris != nullptr);
                REQUIRE(uris->size() == 1U);
                CHECK(text_at(*uris, 0U) == "turn:turn.example.org:3478");
            }
        }
    }

    GIVEN("a server with neither TURN key")
    {
        auto started = merovingian::homeserver::start_client_server(voip_config({}));
        REQUIRE(started.started);
        auto const token = login(started.runtime);

        WHEN("a client asks for TURN credentials")
        {
            auto const response = get(started.runtime, "/_matrix/client/v3/voip/turnServer", token);

            THEN("the answer is the empty object")
            {
                REQUIRE(response.status == 200U);
                CHECK(response.body == "{}");
            }
        }
    }
}
