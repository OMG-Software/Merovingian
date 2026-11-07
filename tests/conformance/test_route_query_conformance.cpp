// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// A request target carries its query string, and a route is the path alone. Every endpoint that
// matched the whole target (`POST /register?kind=user`, an appservice's
// `GET /joined_rooms?user_id=...`) used to miss its handler and answer 405 or 404.
//
// Spec: Matrix Client-Server API v1.19
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3register
//      ../../docs/matrix-v1.19-spec/application-service-api.md#identity-assertion

#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;

[[nodiscard]] auto route_config() -> merovingian::config::Config
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

// The answer of a request no route took: the dispatcher's own, or the local router's.
[[nodiscard]] auto is_unrouted(Reply const& reply) -> bool
{
    return reply.body.find("route not found") != std::string::npos;
}

struct Route final
{
    std::string_view method;
    std::string_view path;
    std::string_view body;
};

} // namespace

// Spec: Matrix Client-Server API v1.19, API standards: an endpoint is its path; "query parameters"
// are not part of it, and an endpoint that does not define one ignores it.
SCENARIO("every client route that matched its whole target answers a request with a query string",
         "[conformance][client-server][route][query-string]")
{
    GIVEN("a running homeserver and a logged-in user")
    {
        auto started = merovingian::homeserver::start_client_server(route_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;
        REQUIRE(
            call(rt, "POST", "/_matrix/client/v3/register", {}, registration_json("alice", "CorrectHorse7!")).status ==
            200U);
        auto const login = call(
            rt, "POST", "/_matrix/client/v3/login", {},
            R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"D1"})");
        REQUIRE(login.status == 200U);
        auto const parsed = parse_object(login.body);
        auto const* token_member = string_member(parsed, "access_token");
        REQUIRE(token_member != nullptr);
        auto const token = *token_member;

        // Every route that was compared with `req.target == "..."`. A handler may answer anything
        // (a UIA challenge, a 400 for the empty body); what it may not do is answer as though the
        // route does not exist. /logout is last: it ends the session.
        constexpr auto routes = std::array<Route, 30>{
            {
             {"GET", "/.well-known/matrix/client", ""},
             {"GET", "/_matrix/client/versions", ""},
             {"POST", "/_matrix/client/v3/register/email/requestToken", "{}"},
             {"POST", "/_matrix/client/v3/register/msisdn/requestToken", "{}"},
             {"POST", "/_matrix/client/v3/register", "{}"},
             {"GET", "/_matrix/client/v3/login", ""},
             {"GET", "/_matrix/client/v3/login/sso/redirect", ""},
             {"POST", "/_matrix/client/v3/login", "{}"},
             {"POST", "/_matrix/client/v3/refresh", "{}"},
             {"POST", "/_matrix/client/v3/account/3pid/email/requestToken", "{}"},
             {"POST", "/_matrix/client/v3/account/3pid/msisdn/requestToken", "{}"},
             {"POST", "/_matrix/client/v3/account/password", "{}"},
             {"POST", "/_matrix/client/v3/account/deactivate", "{}"},
             {"GET", "/_matrix/client/v3/account/3pid", ""},
             {"POST", "/_matrix/client/v3/account/3pid/add", "{}"},
             {"POST", "/_matrix/client/v3/account/3pid/bind", "{}"},
             {"POST", "/_matrix/client/v3/account/3pid", "{}"},
             {"POST", "/_matrix/client/v3/account/3pid/unbind", "{}"},
             {"POST", "/_matrix/client/v3/account/3pid/delete", "{}"},
             {"GET", "/_matrix/client/v3/pushers", ""},
             {"POST", "/_matrix/client/v3/pushers/set", "{}"},
             {"GET", "/_matrix/client/v3/capabilities", ""},
             {"GET", "/_matrix/media/v3/config", ""},
             {"GET", "/_matrix/client/v1/media/config", ""},
             {"GET", "/_matrix/client/v3/voip/turnServer", ""},
             {"GET", "/_matrix/client/v3/devices", ""},
             {"POST", "/_matrix/client/v3/delete_devices", "{}"},
             {"GET", "/_matrix/client/v3/joined_rooms", ""},
             {"POST", "/_matrix/client/v3/user_directory/search", R"({"search_term":"a"})"},
             {"POST", "/_matrix/client/v3/logout", "{}"},
             }
        };

        WHEN("each of them is requested with a harmless query string")
        {
            THEN("none is answered as an unknown route or an unsupported method")
            {
                for (auto const& route : routes)
                {
                    INFO(route.method << ' ' << route.path);
                    auto const reply = call(rt, std::string{route.method}, std::string{route.path} + "?unused=1", token,
                                            std::string{route.body});
                    INFO(reply.status << " " << reply.body);
                    CHECK(reply.status != 405U);
                    CHECK_FALSE(is_unrouted(reply));
                }
            }
        }
    }
}

// Spec: POST /register, query parameter `kind`: "The kind of account to register. Defaults to `user`.
// One of: [guest, user]." The 403 response: "This response can be used to identify that a particular
// `kind` of account is not allowed, or that registration is generally not supported by the homeserver."
SCENARIO("POST /register takes its kind from the query string", "[conformance][client-server][register][kind]")
{
    GIVEN("a running homeserver that offers no guest accounts")
    {
        auto started = merovingian::homeserver::start_client_server(route_config());
        REQUIRE(started.started);
        auto& rt = started.runtime;

        WHEN("a user is registered with kind=user")
        {
            auto const reply = call(rt, "POST", "/_matrix/client/v3/register?kind=user", {},
                                    registration_json("bob", "CorrectHorse7!"));

            THEN("the account is created as with no kind")
            {
                REQUIRE(reply.status == 200U);
                auto const body = parse_object(reply.body);
                auto const* user_id = string_member(body, "user_id");
                REQUIRE(user_id != nullptr);
                CHECK(*user_id == "@bob:example.org");
            }
        }

        WHEN("a guest is requested with kind=guest")
        {
            auto const reply = call(rt, "POST", "/_matrix/client/v3/register?kind=guest", {},
                                    registration_json("carol", "CorrectHorse7!"));

            THEN("it is refused with 403 M_FORBIDDEN and no account is created")
            {
                CHECK(reply.status == 403U);
                CHECK(reply.body.find("M_FORBIDDEN") != std::string::npos);
                auto const& users = rt.homeserver.database.users;
                CHECK(users.empty());
            }
        }

        WHEN("a kind outside the enumeration is requested")
        {
            auto const reply = call(rt, "POST", "/_matrix/client/v3/register?kind=robot", {},
                                    registration_json("dave", "CorrectHorse7!"));

            THEN("it is refused with 400 M_INVALID_PARAM and no account is created")
            {
                CHECK(reply.status == 400U);
                CHECK(reply.body.find("M_INVALID_PARAM") != std::string::npos);
                CHECK(rt.homeserver.database.users.empty());
            }
        }
    }
}
