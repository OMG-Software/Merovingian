// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// ADR-0611: an application service acts for the users of its namespaces in rooms, never as a server administrator,
// whatever user it asserts. These are choices of this server, not Matrix spec, so they are integration tests.
#include "../support/AppserviceTestConfig.hpp"
#include "../support/JsonTestSupport.hpp"
#include "../support/RegistrationToken.hpp"
#include "merovingian/homeserver/AuthService.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/LocalHttpRequest.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <string_view>
#include <utility>

namespace
{

using merovingian::homeserver::ClientServerRuntime;
using merovingian::homeserver::LocalHttpRequest;

constexpr auto password = std::string_view{"CorrectHorse7!"};
constexpr auto as_admin = std::string_view{"?user_id=@admin:example.org"};

[[nodiscard]] auto send(ClientServerRuntime& runtime, std::string method, std::string target, std::string token = {},
                        std::string body = {}) -> merovingian::homeserver::LocalHttpResponse
{
    auto req = LocalHttpRequest{std::move(method), std::move(target), std::move(token), std::move(body)};
    req.remote_addr = "192.0.2.44";
    return merovingian::homeserver::handle_client_server_request(runtime, req).response;
}

[[nodiscard]] auto admin_session(ClientServerRuntime& runtime) -> std::string
{
    auto const response = send(
        runtime, "POST", "/_matrix/client/v3/login", {},
        R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@admin:example.org"},"password":")" +
            std::string{password} + R"(","device_id":"ADMIN_DEV"})");
    REQUIRE(response.status == 200U);
    auto const body = merovingian::tests::parse_object(response.body);
    auto const* token = merovingian::tests::string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto is_locked(ClientServerRuntime& runtime, std::string_view user_id) -> bool
{
    auto const& users = runtime.homeserver.database.users;
    auto const user = std::ranges::find_if(users, [user_id](auto const& candidate) {
        return candidate.user_id == user_id;
    });
    REQUIRE(user != users.end());
    return user->locked;
}

} // namespace

SCENARIO("An application service asserting an administrator is refused by every admin route",
         "[gate-m][admin][masquerade][appservice]")
{
    GIVEN("an application service whose namespace holds the administrator, and an ordinary user")
    {
        auto bridge = merovingian::tests::TestAppservice{.id = "bridge", .users_regex = "@.*:example.org"};
        auto started =
            merovingian::homeserver::start_client_server(merovingian::tests::appservice_test_config({bridge}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::bootstrap_admin_user(runtime.homeserver, "admin", std::string{password}).ok);
        REQUIRE(send(runtime, "POST", "/_matrix/client/v3/register", {},
                     merovingian::tests::registration_json("bob", password))
                    .status == 200U);
        auto const token = bridge.as_token();

        WHEN("it calls the operator routes as the administrator")
        {
            auto const health = send(runtime, "GET", "/_merovingian/admin/health" + std::string{as_admin}, token);
            auto const audit = send(runtime, "GET", "/_merovingian/admin/audit" + std::string{as_admin}, token);
            auto const lock =
                send(runtime, "POST", "/_merovingian/admin/accounts/%40bob%3Aexample.org" + std::string{as_admin},
                     token, R"({"action":"lock"})");

            THEN("each is refused as not an administrator and nothing changes")
            {
                CHECK(health.status == 403U);
                CHECK(audit.status == 403U);
                CHECK(lock.status == 403U);
                CHECK_FALSE(is_locked(runtime, "@bob:example.org"));
            }
        }

        WHEN("it calls the client API's administrator routes as the administrator")
        {
            auto const lock =
                send(runtime, "PUT", "/_matrix/client/v1/admin/lock/%40bob%3Aexample.org" + std::string{as_admin},
                     token, R"({"locked":true})");
            auto const whois = send(
                runtime, "GET", "/_matrix/client/v3/admin/whois/%40bob%3Aexample.org" + std::string{as_admin}, token);
            auto const capabilities =
                send(runtime, "GET", "/_matrix/client/v3/capabilities" + std::string{as_admin}, token);

            THEN("they are refused or answered as for any other user")
            {
                CHECK(lock.status == 403U);
                CHECK_FALSE(is_locked(runtime, "@bob:example.org"));
                CHECK(whois.status == 403U);
                REQUIRE(capabilities.status == 200U);
                CHECK(capabilities.body.find("m.account_moderation") == std::string::npos);
            }
        }

        WHEN("the same application service acts as an ordinary user on a route for users")
        {
            auto const joined =
                send(runtime, "GET", "/_matrix/client/v3/joined_rooms?user_id=@admin:example.org", token);

            THEN("the assertion still works where the spec gives it")
            {
                CHECK(joined.status == 200U);
            }
        }

        WHEN("the administrator calls the same routes with their own session")
        {
            auto const session = admin_session(runtime);
            auto const health = send(runtime, "GET", "/_merovingian/admin/health", session);
            auto const lock = send(runtime, "POST", "/_merovingian/admin/accounts/%40bob%3Aexample.org", session,
                                   R"({"action":"lock"})");

            THEN("they are served")
            {
                CHECK(health.status == 200U);
                CHECK(lock.status == 200U);
                CHECK(is_locked(runtime, "@bob:example.org"));
            }
        }

        WHEN("an operator route is called with a token that is nobody's")
        {
            auto const health = send(runtime, "GET", "/_merovingian/admin/health", "not-a-token");

            THEN("it is unauthenticated, not forbidden")
            {
                CHECK(health.status == 401U);
            }
        }
    }
}
