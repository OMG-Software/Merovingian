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
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/generators/catch_generators.hpp>

#include <cstddef>
#include <string>
#include <tuple>
#include <utility>
#include <variant>
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
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_json("alice", "CorrectHorse7!")})
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
                auto const* username = string_member(body, "username");
                REQUIRE(username != nullptr);
                CHECK(*username == "turnuser");
                auto const* password = string_member(body, "password");
                REQUIRE(password != nullptr);
                CHECK(*password == "turnpass");
                auto const* ttl = int_member(body, "ttl");
                REQUIRE(ttl != nullptr);
                CHECK(*ttl == 600);
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

namespace
{

constexpr auto livekit_url = "https://livekit-jwt.example.org/lk-jwt-service";

[[nodiscard]] auto rtc_server(std::string url) -> merovingian::config::ServerConfig
{
    auto server = merovingian::config::ServerConfig{};
    server.rtc.livekit_service_url = std::move(url);
    return server;
}

} // namespace

// The same configured LiveKit service URL is served on two routes that differ in path and in the name of the array:
// the stable route as `transports`, the MSC4143 unstable route as `rtc_transports`. A client written against either
// must find the same single entry. With no URL configured neither route fails: the two answer their own empty shape.
SCENARIO("MatrixRTC transports are advertised on the stable and unstable paths", "[homeserver][rtc][client-server]")
{
    GIVEN("a server with a LiveKit service URL")
    {
        auto started = merovingian::homeserver::start_client_server(voip_config(rtc_server(livekit_url)));
        REQUIRE(started.started);
        auto const token = login(started.runtime);

        WHEN("a client reads the stable transports route")
        {
            auto const response = get(started.runtime, "/_matrix/client/v1/rtc/transports", token);

            THEN("it gets a livekit transport under `transports`")
            {
                REQUIRE(response.status == 200U);
                auto const body = parse_object(response.body);
                auto const* transports = object_member_as_array(body, "transports");
                REQUIRE(transports != nullptr);
                REQUIRE(transports->size() == 1U);
                // The exact body pins the serialised form (keys in canonical order, nothing extra) ...
                CHECK(
                    response.body ==
                    R"({"transports":[{"livekit_service_url":"https://livekit-jwt.example.org/lk-jwt-service","type":"livekit"}]})");
                auto const* entry = std::get_if<merovingian::canonicaljson::Object>(&(*transports)[0U].storage());
                REQUIRE(entry != nullptr);
                // ... and the parsed checks name the two members a client reads, so a failure points at the member.
                CHECK(entry->size() == 2U);
                auto const* type = string_member(*entry, "type");
                REQUIRE(type != nullptr);
                CHECK(*type == "livekit");
                auto const* service_url = string_member(*entry, "livekit_service_url");
                REQUIRE(service_url != nullptr);
                CHECK(*service_url == livekit_url);
            }
        }

        // The query string is ignored by the route, as on the other client-server routes, but must not stop the route
        // from matching.
        WHEN("a client reads the unstable transports route, with a query string")
        {
            auto const response =
                get(started.runtime, "/_matrix/client/unstable/org.matrix.msc4143/rtc/transports?unused=1", token);

            THEN("it gets the same entry under `rtc_transports`")
            {
                REQUIRE(response.status == 200U);
                auto const body = parse_object(response.body);
                CHECK(
                    response.body ==
                    R"({"rtc_transports":[{"livekit_service_url":"https://livekit-jwt.example.org/lk-jwt-service","type":"livekit"}]})");
                auto const* transports = object_member_as_array(body, "rtc_transports");
                REQUIRE(transports != nullptr);
                REQUIRE(transports->size() == 1U);
                auto const* entry = std::get_if<merovingian::canonicaljson::Object>(&(*transports)[0U].storage());
                REQUIRE(entry != nullptr);
                CHECK(entry->size() == 2U);
                auto const* type = string_member(*entry, "type");
                REQUIRE(type != nullptr);
                CHECK(*type == "livekit");
                auto const* service_url = string_member(*entry, "livekit_service_url");
                REQUIRE(service_url != nullptr);
                CHECK(*service_url == livekit_url);
            }
        }

        // The stable route's own match with a query string; the unstable one is covered by the previous WHEN.
        WHEN("a client reads the stable route with a query string")
        {
            auto const response = get(started.runtime, "/_matrix/client/v1/rtc/transports?unused=1", token);

            THEN("it still routes")
            {
                CHECK(response.status == 200U);
            }
        }
    }

    // Without a URL the feature is off, but a client that asks is not told an error: it gets an empty answer in the
    // shape of each route, so it can tell "none offered" from "route unknown".
    GIVEN("a server with no LiveKit service URL")
    {
        auto started = merovingian::homeserver::start_client_server(voip_config({}));
        REQUIRE(started.started);
        auto const token = login(started.runtime);

        WHEN("a client reads each route")
        {
            auto const stable = get(started.runtime, "/_matrix/client/v1/rtc/transports", token);
            auto const unstable =
                get(started.runtime, "/_matrix/client/unstable/org.matrix.msc4143/rtc/transports", token);

            THEN("the stable path answers an empty list and the unstable path an empty object")
            {
                REQUIRE(stable.status == 200U);
                CHECK(stable.body == R"({"transports":[]})");
                REQUIRE(unstable.status == 200U);
                CHECK(unstable.body == "{}");
            }
        }
    }
}

SCENARIO("MatrixRTC transports need an access token", "[homeserver][rtc][client-server]")
{
    GIVEN("a server with a LiveKit service URL")
    {
        auto started = merovingian::homeserver::start_client_server(voip_config(rtc_server(livekit_url)));
        REQUIRE(started.started);
        std::ignore = login(started.runtime);

        WHEN("each route is read without a token, and with an unknown one")
        {
            THEN("each answers 401 and names no URL")
            {
                for (auto const* path : {"/_matrix/client/v1/rtc/transports",
                                         "/_matrix/client/unstable/org.matrix.msc4143/rtc/transports"})
                {
                    INFO(path);
                    auto const none = get(started.runtime, path);
                    auto const unknown = get(started.runtime, path, "not-a-token");
                    CHECK(none.status == 401U);
                    CHECK(unknown.status == 401U);
                    CHECK(none.body.find("livekit") == std::string::npos);
                    CHECK(unknown.body.find("livekit") == std::string::npos);
                }
            }
        }
    }
}

SCENARIO("/versions announces MatrixRTC discovery whether or not a service is configured",
         "[homeserver][rtc][client-server]")
{
    GIVEN("servers with and without a LiveKit service URL")
    {
        auto with_url = merovingian::homeserver::start_client_server(voip_config(rtc_server(livekit_url)));
        auto without = merovingian::homeserver::start_client_server(voip_config({}));
        REQUIRE(with_url.started);
        REQUIRE(without.started);

        WHEN("/versions is read on each")
        {
            auto const a = get(with_url.runtime, "/_matrix/client/versions");
            auto const b = get(without.runtime, "/_matrix/client/versions");

            THEN("both carry org.matrix.msc4143 and org.matrix.msc4143.stable as true")
            {
                for (auto const* response : {&a, &b})
                {
                    REQUIRE(response->status == 200U);
                    auto const body = parse_object(response->body);
                    auto const* features = object_member_as_object(body, "unstable_features");
                    REQUIRE(features != nullptr);
                    for (auto const* flag : {"org.matrix.msc4143", "org.matrix.msc4143.stable"})
                    {
                        auto const* value = bool_member(*features, flag);
                        REQUIRE(value != nullptr);
                        CHECK(*value);
                    }
                    CHECK(bool_member(*features, "org.matrix.msc4186") != nullptr);
                }
            }
        }
    }
}

SCENARIO("/.well-known/matrix/client carries rtc_foci only when a service is configured",
         "[homeserver][rtc][client-server]")
{
    GIVEN("a server with a LiveKit service URL and a public base URL")
    {
        auto server = rtc_server(livekit_url);
        server.public_baseurl = "https://matrix.example.org";
        auto started = merovingian::homeserver::start_client_server(voip_config(std::move(server)));
        REQUIRE(started.started);

        WHEN("the well-known document is read")
        {
            auto const response = get(started.runtime, "/.well-known/matrix/client");

            THEN("it adds org.matrix.msc4143.rtc_foci beside m.homeserver")
            {
                REQUIRE(response.status == 200U);
                auto const body = parse_object(response.body);
                CHECK(
                    response.body ==
                    R"({"m.homeserver":{"base_url":"https://matrix.example.org"},"org.matrix.msc4143.rtc_foci":[{"livekit_service_url":"https://livekit-jwt.example.org/lk-jwt-service","type":"livekit"}]})");
                REQUIRE(object_member_as_object(body, "m.homeserver") != nullptr);
                auto const* foci = object_member_as_array(body, "org.matrix.msc4143.rtc_foci");
                REQUIRE(foci != nullptr);
                REQUIRE(foci->size() == 1U);
                auto const* entry = std::get_if<merovingian::canonicaljson::Object>(&(*foci)[0U].storage());
                REQUIRE(entry != nullptr);
                CHECK(entry->size() == 2U);
                auto const* type = string_member(*entry, "type");
                REQUIRE(type != nullptr);
                CHECK(*type == "livekit");
                auto const* service_url = string_member(*entry, "livekit_service_url");
                REQUIRE(service_url != nullptr);
                CHECK(*service_url == livekit_url);
            }
        }
    }

    GIVEN("a server with no LiveKit service URL")
    {
        auto server = merovingian::config::ServerConfig{};
        server.public_baseurl = "https://matrix.example.org";
        auto started = merovingian::homeserver::start_client_server(voip_config(std::move(server)));
        REQUIRE(started.started);

        WHEN("the well-known document is read")
        {
            auto const response = get(started.runtime, "/.well-known/matrix/client");

            THEN("the body is exactly what it was before MatrixRTC")
            {
                REQUIRE(response.status == 200U);
                CHECK(response.body == R"({"m.homeserver":{"base_url":"https://matrix.example.org"}})");
            }
        }
    }
}

namespace
{

[[nodiscard]] auto send(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& method,
                        std::string const& target, std::string const& token = {})
    -> merovingian::homeserver::LocalHttpResponse
{
    return merovingian::homeserver::handle_client_server_request(runtime, {method, target, token, {}}).response;
}

[[nodiscard]] auto header_of(merovingian::homeserver::LocalHttpResponse const& response, std::string_view name)
    -> std::string
{
    for (auto const& [header_name, value] : response.headers)
    {
        if (header_name == name)
        {
            return value;
        }
    }
    return {};
}

[[nodiscard]] auto errcode_of(merovingian::homeserver::LocalHttpResponse const& response) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* errcode = string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

constexpr auto turn_path = "/_matrix/client/v3/voip/turnServer";
constexpr auto rtc_stable_path = "/_matrix/client/v1/rtc/transports";
constexpr auto rtc_unstable_path = "/_matrix/client/unstable/org.matrix.msc4143/rtc/transports";

} // namespace

SCENARIO("The MatrixRTC routes refuse other methods as voip/turnServer does", "[homeserver][rtc][client-server]")
{
    GIVEN("a server with a LiveKit service URL and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(voip_config(rtc_server(livekit_url)));
        REQUIRE(started.started);
        auto const token = login(started.runtime);

        WHEN("POST and PUT are sent to each route and to voip/turnServer")
        {
            THEN("each route answers the same status, errcode and Allow header as voip/turnServer")
            {
                for (auto const* method : {"POST", "PUT"})
                {
                    auto const reference = send(started.runtime, method, turn_path, token);
                    REQUIRE(reference.status == 405U);
                    for (auto const* path : {rtc_stable_path, rtc_unstable_path})
                    {
                        INFO(method << ' ' << path);
                        auto const response = send(started.runtime, method, path, token);
                        CHECK(response.status == reference.status);
                        CHECK(errcode_of(response) == errcode_of(reference));
                        CHECK(header_of(response, "Allow") == header_of(reference, "Allow"));
                        CHECK(header_of(response, "Allow") == "GET");
                    }
                }
            }
        }
    }
}

SCENARIO("The MatrixRTC routes treat a locked or suspended account as voip/turnServer does",
         "[homeserver][rtc][client-server]")
{
    GIVEN("a logged-in user whose account is then locked or suspended")
    {
        auto server = rtc_server(livekit_url);
        server.turn.server = "turn:turn.example.org:3478";
        server.turn.username = "turnuser";
        server.turn.password = "turnpass";
        auto started = merovingian::homeserver::start_client_server(voip_config(std::move(server)));
        REQUIRE(started.started);
        auto const token = login(started.runtime);
        auto const suspended = GENERATE(false, true);
        REQUIRE(
            merovingian::homeserver::bootstrap_admin_user(started.runtime.homeserver, "admin", "CorrectHorse7!").ok);
        REQUIRE(merovingian::homeserver::set_local_user_moderation(started.runtime.homeserver, "@admin:example.org",
                                                                   "@alice:example.org", suspended, !suspended,
                                                                   "account.locked", "locked")
                    .ok);

        WHEN("the user asks for TURN credentials and for each transports route")
        {
            auto const reference = send(started.runtime, "GET", turn_path, token);

            THEN("each route answers the same status and errcode, and a refusal names no service URL")
            {
                for (auto const* path : {rtc_stable_path, rtc_unstable_path})
                {
                    INFO((suspended ? "suspended " : "locked ") << path);
                    auto const response = send(started.runtime, "GET", path, token);
                    CHECK(response.status == reference.status);
                    CHECK(errcode_of(response) == errcode_of(reference));
                    if (reference.status != 200U)
                    {
                        CHECK(response.body.find("livekit") == std::string::npos);
                    }
                }
            }
        }
    }
}

SCENARIO("With only server.turn.server and static credentials voip/turnServer answers as in 1.0.x",
         "[homeserver][turn][client-server]")
{
    GIVEN("a server configured the 1.0.x way")
    {
        auto server = merovingian::config::ServerConfig{};
        server.turn.server = "turn:turn.example.org:3478?transport=udp";
        server.turn.username = "turnuser";
        server.turn.password = "turnpass";
        auto started = merovingian::homeserver::start_client_server(voip_config(std::move(server)));
        REQUIRE(started.started);
        auto const token = login(started.runtime);

        WHEN("a client asks for TURN credentials")
        {
            auto const response = get(started.runtime, turn_path, token);

            THEN("the whole body is the one the 1.0 series sent")
            {
                REQUIRE(response.status == 200U);
                CHECK(
                    response.body ==
                    R"({"password":"turnpass","ttl":86400,"uris":["turn:turn.example.org:3478?transport=udp"],"username":"turnuser"})");
            }
        }
    }
}
