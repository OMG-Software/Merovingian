// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// A profile field a user has not set is absent from what the server returns, not an empty string.
//
// Spec: Matrix Client-Server API v1.19, GET /profile/{userId}: `avatar_url` is "The user's avatar URL if they
// have set one, otherwise not present." and `displayname` is "The user's display name if they have set one,
// otherwise not present."; POST /user_directory/search results: `avatar_url` and `display_name` are "if one
// exists".
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3profileuserid
//      ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3user_directorysearch

#include "../support/InMemoryDatabaseConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/MasterKey.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <string>
#include <tuple>
#include <utility>
#include <variant>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto profile_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

struct Reply final
{
    std::uint16_t status{0U};
    std::string body{};
};

[[nodiscard]] auto call(ClientServerRuntime& rt, std::string method, std::string target, std::string const& token,
                        std::string body = {}) -> Reply
{
    auto const result = merovingian::homeserver::handle_client_server_request(
        rt, {std::move(method), std::move(target), token, std::move(body)}, /*can_wait=*/false);
    return {static_cast<std::uint16_t>(result.response.status), result.response.body};
}

[[nodiscard]] auto register_and_login(ClientServerRuntime& rt, std::string const& localpart) -> std::string
{
    REQUIRE(
        call(rt, "POST", "/_matrix/client/v3/register", {}, registration_json(localpart, "CorrectHorse7!")).status ==
        200U);
    auto const login =
        call(rt, "POST", "/_matrix/client/v3/login", {},
             std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} + localpart +
                 R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + localpart + R"(_DEV"})");
    REQUIRE(login.status == 200U);
    auto const body = parse_object(login.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: GET /profile/{userId}, GET /profile/{userId}/{keyName}, POST /user_directory/search
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#get_matrixclientv3profileuserid
//
// `avatar_url` and `displayname` are "otherwise not present" when unset; a single unset field is 404.
SCENARIO("GET /profile/{userId} leaves out a field the user has not set",
         "[conformance][client-server][profile][profile-unset]")
{
    // Baseline setup: create a user that has never set profile metadata so both fields are unset.
    GIVEN("a user who has set neither a display name nor an avatar")
    {
        auto started = merovingian::homeserver::start_client_server(profile_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        std::ignore = register_and_login(rt, "alice");

        WHEN("the profile is read")
        {
            auto const reply = call(rt, "GET", "/_matrix/client/v3/profile/@alice:example.org", {});

            THEN("it is a 200 with neither field present")
            {
                // For the aggregate profile endpoint, unset keys must be omitted rather than returned empty/null.
                REQUIRE(reply.status == 200U);
                auto const body = parse_object(reply.body);
                REQUIRE(object_member(body, "displayname") == nullptr);
                REQUIRE(object_member(body, "avatar_url") == nullptr);
            }
        }

        WHEN("a single unset field is read")
        {
            auto const name = call(rt, "GET", "/_matrix/client/v3/profile/@alice:example.org/displayname", {});
            auto const avatar = call(rt, "GET", "/_matrix/client/v3/profile/@alice:example.org/avatar_url", {});

            THEN("each is a 404 M_NOT_FOUND with no empty value")
            {
                // Field-specific endpoints must signal absence with M_NOT_FOUND, not with an empty value payload.
                REQUIRE(name.status == 404U);
                REQUIRE(avatar.status == 404U);
                REQUIRE(name.body.find("M_NOT_FOUND") != std::string::npos);
                REQUIRE(avatar.body.find("M_NOT_FOUND") != std::string::npos);
            }
        }
    }

    GIVEN("a user who has set only a display name")
    {
        auto started = merovingian::homeserver::start_client_server(profile_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        REQUIRE(call(rt, "PUT", "/_matrix/client/v3/profile/@alice:example.org/displayname", token,
                     R"({"displayname":"Alice"})")
                    .status == 200U);

        WHEN("the profile is read")
        {
            auto const reply = call(rt, "GET", "/_matrix/client/v3/profile/@alice:example.org", {});

            THEN("the display name is present and the avatar is not")
            {
                REQUIRE(reply.status == 200U);
                auto const body = parse_object(reply.body);
                auto const* name = string_member(body, "displayname");
                REQUIRE(name != nullptr);
                REQUIRE(*name == "Alice");
                REQUIRE(object_member(body, "avatar_url") == nullptr);
            }
        }

        WHEN("the user searches for themselves in the user directory")
        {
            // The directory lists a user found through a public room.
            REQUIRE(call(rt, "POST", "/_matrix/client/v3/createRoom", token, R"({"preset":"public_chat"})").status ==
                    200U);
            auto const reply =
                call(rt, "POST", "/_matrix/client/v3/user_directory/search", token, R"({"search_term":"alice"})");

            THEN("the result has a display_name and no avatar_url member")
            {
                REQUIRE(reply.status == 200U);
                auto const body = parse_object(reply.body);
                auto const* results = object_member_as_array(body, "results");
                REQUIRE(results != nullptr);
                REQUIRE(results->size() == 1U);
                auto const* entry = std::get_if<merovingian::canonicaljson::Object>(&(*results)[0].storage());
                REQUIRE(entry != nullptr);
                REQUIRE(string_member(*entry, "display_name") != nullptr);
                REQUIRE(object_member(*entry, "avatar_url") == nullptr);
            }
        }
    }

    GIVEN("a user who set an avatar and then cleared it")
    {
        auto started = merovingian::homeserver::start_client_server(profile_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        auto const token = register_and_login(rt, "alice");
        REQUIRE(call(rt, "PUT", "/_matrix/client/v3/profile/@alice:example.org/avatar_url", token,
                     R"({"avatar_url":"mxc://example.org/abc"})")
                    .status == 200U);
        REQUIRE(
            call(rt, "PUT", "/_matrix/client/v3/profile/@alice:example.org/avatar_url", token, R"({"avatar_url":""})")
                .status == 200U);

        WHEN("the profile is read")
        {
            auto const reply = call(rt, "GET", "/_matrix/client/v3/profile/@alice:example.org", {});

            THEN("the avatar is not present")
            {
                REQUIRE(reply.status == 200U);
                REQUIRE(object_member(parse_object(reply.body), "avatar_url") == nullptr);
            }
        }
    }
}
