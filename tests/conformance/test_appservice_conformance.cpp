// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         APPLICATION SERVICE API — as_token AUTH & MASQUERADING          |
// |                                                                         |
// |  Spec: Matrix Application Service API v1.19                            |
// |  URL:  ../../docs/matrix-v1.19-spec/application-service-api.md          |
// |                                                                         |
// |  Covers the client-server-surface half of the Application Service API: |
// |  as_token bearer auth, `?user_id=` identity-assertion masquerade,      |
// |  `m.login.application_service` register/login, and namespace           |
// |  exclusivity. Outbound transactions/queries and `/thirdparty/*` are    |
// |  covered elsewhere as they land.                                       |
// +-------------------------------------------------------------------------+

#include "../support/json_test_support.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto irc_bridge_registration_json() -> std::string
{
    return R"({
        "id": "irc-bridge",
        "url": "http://127.0.0.1:1234",
        "as_token": "irc-bridge-as-token-secret",
        "hs_token": "irc-bridge-hs-token-secret",
        "sender_localpart": "_irc_bot",
        "namespaces": {
            "users": [{"exclusive": true, "regex": "@_irc_bridge_.*"}],
            "aliases": [{"exclusive": true, "regex": "#_irc_bridge_.*"}],
            "rooms": []
        }
    })";
}

// Writes the fixed IRC bridge registration to a fresh temp file and returns
// a Config wired to load it. Every scenario gets its own file so scenarios
// never interfere with each other's on-disk state.
[[nodiscard]] auto conformance_config_with_appservice(std::filesystem::path const& registration_path)
    -> merovingian::config::Config
{
    {
        auto out = std::ofstream{registration_path, std::ios::binary};
        out << irc_bridge_registration_json();
    }
    auto security = merovingian::config::SecurityConfig{};
    // Ordinary (non-appservice) registration must stay reachable so the
    // exclusivity scenarios below can prove a HUMAN is blocked from an
    // exclusive namespace, not merely that registration itself is off.
    // m.login.application_service registration bypasses this entirely
    // (register_appservice_user never consults security.registration) —
    // see its own scenario for that path.
    merovingian::tests::enable_token_registration(security);
    auto config = merovingian::config::Config{
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
    config.appservice().registration_files = {registration_path.string()};
    return config;
}

} // namespace

SCENARIO("an appservice's as_token authenticates as its sender_localpart by default", "[appservice][conformance][auth]")
{
    // Spec: "If the [user_id] parameter is missing, the homeserver is to
    // assume the application service intends to act as the user implied by
    // the sender_localpart property of the registration."
    GIVEN("a homeserver with one registered appservice")
    {
        auto const path = std::filesystem::temp_directory_path() / "merovingian-conformance-as-default.json";
        auto const config = conformance_config_with_appservice(path);
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("GET /account/whoami is called with the appservice's as_token and no ?user_id=")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/account/whoami", "irc-bridge-as-token-secret", {}});

            THEN("the caller is identified as the appservice's own sender_localpart user")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* user_id = string_member(body, "user_id");
                REQUIRE(user_id != nullptr);
                CHECK(*user_id == "@_irc_bot:example.org");
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("?user_id= masquerades as a user within the appservice's namespace", "[appservice][conformance][auth]")
{
    // Spec: "The application service may specify the virtual user to act as
    // through use of a `user_id` query string parameter ... The user
    // specified ... must be covered by one of the application service's
    // `user` namespaces."
    GIVEN("a homeserver with one registered appservice")
    {
        auto const path = std::filesystem::temp_directory_path() / "merovingian-conformance-as-masquerade.json";
        auto const config = conformance_config_with_appservice(path);
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("whoami is called with ?user_id= naming a user inside the users namespace")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET",
                          "/_matrix/client/v3/account/whoami?user_id=@_irc_bridge_alice:example.org",
                          "irc-bridge-as-token-secret",
                          {}});

            THEN("the caller is identified as that virtual user")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* user_id = string_member(body, "user_id");
                REQUIRE(user_id != nullptr);
                CHECK(*user_id == "@_irc_bridge_alice:example.org");
            }
        }

        WHEN("whoami is called with ?user_id= naming a user OUTSIDE any namespace")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET",
                          "/_matrix/client/v3/account/whoami?user_id=@carol:example.org",
                          "irc-bridge-as-token-secret",
                          {}});

            THEN("the request is rejected, never silently falling back")
            {
                REQUIRE(response.response.status == 403U);
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("m.login.application_service registers and logs in a passwordless virtual user",
         "[appservice][conformance][auth]")
{
    // Spec §"Server admin style permissions": "This is achieved by including
    // the as_token on a /register request, along with a login type of
    // m.login.application_service to set the desired user ID without a
    // password."
    GIVEN("a homeserver with one registered appservice")
    {
        auto const path = std::filesystem::temp_directory_path() / "merovingian-conformance-as-register.json";
        auto const config = conformance_config_with_appservice(path);
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("POST /register is called with as_token bearer auth and a namespaced username")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/register", "irc-bridge-as-token-secret",
                          R"({"type":"m.login.application_service","username":"_irc_bridge_bob"})"});

            THEN("registration succeeds and a real session is issued (inhibit_login defaults to false)")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* user_id = string_member(body, "user_id");
                auto const* access_token = string_member(body, "access_token");
                REQUIRE(user_id != nullptr);
                REQUIRE(access_token != nullptr);
                CHECK(*user_id == "@_irc_bridge_bob:example.org");

                AND_THEN("the issued token authenticates as that user on an ordinary request")
                {
                    auto const whoami = merovingian::homeserver::handle_client_server_request(
                        runtime, {"GET", "/_matrix/client/v3/account/whoami", *access_token, {}});
                    REQUIRE(whoami.response.status == 200U);
                    auto const whoami_body = parse_object(whoami.response.body);
                    auto const* whoami_user_id = string_member(whoami_body, "user_id");
                    REQUIRE(whoami_user_id != nullptr);
                    CHECK(*whoami_user_id == "@_irc_bridge_bob:example.org");
                }
            }
        }

        WHEN("POST /register with m.login.application_service names a username outside the namespace")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/register", "irc-bridge-as-token-secret",
                          R"({"type":"m.login.application_service","username":"carol"})"});

            THEN("the server rejects it with M_EXCLUSIVE")
            {
                // Spec: "Application services which attempt to create users
                // or aliases outside of their defined namespaces ... will
                // receive an error code M_EXCLUSIVE."
                REQUIRE(response.response.status == 403U);
                CHECK(response.response.body.find("M_EXCLUSIVE") != std::string::npos);
            }
        }

        WHEN("POST /register with m.login.application_service is called without a valid as_token")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/register", "not-a-real-as-token",
                          R"({"type":"m.login.application_service","username":"_irc_bridge_bob"})"});

            THEN("the server rejects it as an unknown token, per the ordinary client-server auth contract")
            {
                // Spec: "the endpoints will return an error with the
                // M_MISSING_TOKEN or M_UNKNOWN_TOKEN error code and 401 as
                // the HTTP status code."
                REQUIRE(response.response.status == 401U);
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("m.login.application_service logs an existing virtual user in without a password",
         "[appservice][conformance][auth]")
{
    GIVEN("a virtual user already registered by the appservice")
    {
        auto const path = std::filesystem::temp_directory_path() / "merovingian-conformance-as-login.json";
        auto const config = conformance_config_with_appservice(path);
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const registered = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/register", "irc-bridge-as-token-secret",
                      R"({"type":"m.login.application_service","username":"_irc_bridge_dave","inhibit_login":true})"});
        REQUIRE(registered.response.status == 200U);

        WHEN("POST /login is called with m.login.application_service naming that user")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST", "/_matrix/client/v3/login", "irc-bridge-as-token-secret",
                 R"({"type":"m.login.application_service","identifier":{"type":"m.id.user","user":"_irc_bridge_dave"}})"});

            THEN("a real session for that user is returned, with no password involved")
            {
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* user_id = string_member(body, "user_id");
                auto const* access_token = string_member(body, "access_token");
                REQUIRE(user_id != nullptr);
                REQUIRE(access_token != nullptr);
                CHECK(*user_id == "@_irc_bridge_dave:example.org");
            }
        }

        std::filesystem::remove(path);
    }
}

SCENARIO("GET /login advertises m.login.application_service", "[appservice][conformance][auth]")
{
    GIVEN("any homeserver")
    {
        auto const config = merovingian::config::Config{
            merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
            merovingian::config::DatabaseConfig{},         merovingian::config::SecurityConfig{},
            merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
        };
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("GET /_matrix/client/v3/login is called")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/login", {}, {}});

            THEN("m.login.application_service is one of the advertised flows")
            {
                REQUIRE(response.response.status == 200U);
                CHECK(response.response.body.find("m.login.application_service") != std::string::npos);
            }
        }
    }
}

SCENARIO("an exclusive namespace blocks a human from registering or creating an alias within it",
         "[appservice][conformance][exclusivity]")
{
    // Spec: "normal users who attempt to create users or aliases inside an
    // application service-defined namespace will receive the same
    // M_EXCLUSIVE error code, but only if the application service has
    // defined the namespace as exclusive."
    GIVEN("a homeserver with an appservice owning an exclusive users and aliases namespace")
    {
        auto const path = std::filesystem::temp_directory_path() / "merovingian-conformance-as-exclusivity.json";
        auto const config = conformance_config_with_appservice(path);
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("an ordinary human registers a username inside the exclusive users namespace")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          registration_json("_irc_bridge_intruder", "CorrectHorse7!")});

            THEN("registration is rejected with M_EXCLUSIVE")
            {
                REQUIRE(response.response.status == 400U);
                CHECK(response.response.body.find("M_EXCLUSIVE") != std::string::npos);
            }
        }

        WHEN("an ordinary human, already registered, tries to claim an alias inside the exclusive aliases namespace")
        {
            auto const reg = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/register", {}, registration_json("plainuser", "CorrectHorse7!")});
            REQUIRE(reg.response.status == 200U);
            auto const reg_body = parse_object(reg.response.body);
            auto const* token = string_member(reg_body, "access_token");
            REQUIRE(token != nullptr);
            auto const room = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", *token, "{}"});
            REQUIRE(room.response.status == 200U);
            auto const room_body = parse_object(room.response.body);
            auto const* room_id = string_member(room_body, "room_id");
            REQUIRE(room_id != nullptr);

            auto const alias_response = merovingian::homeserver::handle_client_server_request(
                runtime, {"PUT", "/_matrix/client/v3/directory/room/%23_irc_bridge_channel%3Aexample.org", *token,
                          R"({"room_id":")" + *room_id + R"("})"});

            THEN("alias creation is rejected with M_EXCLUSIVE")
            {
                REQUIRE(alias_response.response.status == 400U);
                CHECK(alias_response.response.body.find("M_EXCLUSIVE") != std::string::npos);
            }
        }

        std::filesystem::remove(path);
    }
}
