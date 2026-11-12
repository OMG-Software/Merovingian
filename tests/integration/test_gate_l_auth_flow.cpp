// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Release-gate audit, low findings, authorization and room semantics. These are decisions of this server (ADR-0626 to
// ADR-0631) or spec-silent behaviour, so they are integration tests.
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
using merovingian::tests::parse_object;
using merovingian::tests::string_member;

constexpr auto password = std::string_view{"CorrectHorse7!"};

[[nodiscard]] auto send(ClientServerRuntime& runtime, std::string method, std::string target, std::string token = {},
                        std::string body = {}) -> merovingian::homeserver::LocalHttpResponse
{
    auto req = LocalHttpRequest{std::move(method), std::move(target), std::move(token), std::move(body)};
    req.remote_addr = "192.0.2.44";
    return merovingian::homeserver::handle_client_server_request(runtime, req).response;
}

[[nodiscard]] auto login(ClientServerRuntime& runtime, std::string const& name) -> std::string
{
    auto const response =
        send(runtime, "POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + name +
                 R"(:example.org"},"password":")" + std::string{password} + R"(","device_id":")" + name + R"(_DEV"})");
    REQUIRE(response.status == 200U);
    auto const body = parse_object(response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto register_and_login(ClientServerRuntime& runtime, std::string const& name) -> std::string
{
    REQUIRE(
        send(runtime, "POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json(name, password))
            .status == 200U);
    return login(runtime, name);
}

void deactivate_in_memory(ClientServerRuntime& runtime, std::string_view user_id)
{
    auto& users = runtime.homeserver.database.users;
    auto const user = std::ranges::find_if(users, [user_id](auto const& candidate) {
        return candidate.user_id == user_id;
    });
    REQUIRE(user != users.end());
    user->deactivated = true;
}

[[nodiscard]] auto member_string(std::string const& body, std::string_view key) -> std::string
{
    auto const parsed = parse_object(body);
    auto const* value = string_member(parsed, key);
    REQUIRE(value != nullptr);
    return *value;
}

} // namespace

// A decision of this server (ADR-0626): the access-token gate refuses a deactivated account whose tokens are still
// live, because login, refresh and OpenID already do. A token is unknown to the spec (401 M_UNKNOWN_TOKEN) once the
// account is gone.
SCENARIO("A deactivated account's still-live access token is refused", "[gate-l][auth][deactivated]")
{
    GIVEN("an administrator and an ordinary user with live tokens")
    {
        auto started = merovingian::homeserver::start_client_server(merovingian::tests::appservice_test_config({}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::bootstrap_admin_user(runtime.homeserver, "admin", std::string{password}).ok);
        auto const admin_token = login(runtime, "admin");
        auto const bob_token = register_and_login(runtime, "bob");
        REQUIRE(send(runtime, "GET", "/_matrix/client/v3/joined_rooms", bob_token).status == 200U);
        REQUIRE(send(runtime, "GET", "/_merovingian/admin/health", admin_token).status == 200U);

        WHEN("bob is deactivated but his token was not revoked")
        {
            deactivate_in_memory(runtime, "@bob:example.org");
            auto const joined = send(runtime, "GET", "/_matrix/client/v3/joined_rooms", bob_token);
            auto const create = send(runtime, "POST", "/_matrix/client/v3/createRoom", bob_token, "{}");

            THEN("the token is unknown")
            {
                REQUIRE(joined.status == 401U);
                REQUIRE(member_string(joined.body, "errcode") == "M_UNKNOWN_TOKEN");
                REQUIRE(create.status == 401U);
            }
            AND_THEN("the administrator is unaffected")
            {
                REQUIRE(send(runtime, "GET", "/_matrix/client/v3/joined_rooms", admin_token).status == 200U);
            }
        }

        WHEN("the administrator is deactivated but the token was not revoked")
        {
            deactivate_in_memory(runtime, "@admin:example.org");
            auto const health = send(runtime, "GET", "/_merovingian/admin/health", admin_token);
            auto const client_admin =
                send(runtime, "GET", "/_matrix/client/v3/admin/whois/%40bob%3Aexample.org", admin_token);

            THEN("the operator surface and the client administrator routes refuse the token")
            {
                REQUIRE(health.status == 401U);
                REQUIRE(client_admin.status == 401U);
            }
            AND_THEN("the in-process gates refuse it too")
            {
                REQUIRE_FALSE(merovingian::homeserver::authenticated_user(runtime.homeserver, admin_token).has_value());
                REQUIRE_FALSE(
                    merovingian::homeserver::authenticated_session(runtime.homeserver, admin_token).has_value());
                REQUIRE_FALSE(
                    merovingian::homeserver::authenticated_admin_user(runtime.homeserver, admin_token).has_value());
                REQUIRE_FALSE(
                    merovingian::homeserver::require_admin(runtime.homeserver, admin_token).user_id.has_value());
            }
        }
    }
}

// A decision of this server (ADR-0627): the spec leaves the content of the replacement room's create event to the
// implementation, and a room made with `m.federate: false` can never change it.
SCENARIO("A room upgrade keeps a room local-only", "[gate-l][rooms][upgrade][federate]")
{
    GIVEN("a room created with m.federate false and one created without it")
    {
        auto started = merovingian::homeserver::start_client_server(merovingian::tests::appservice_test_config({}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_and_login(runtime, "alice");
        auto const local_only = member_string(
            send(runtime, "POST", "/_matrix/client/v3/createRoom", alice,
                 R"({"preset":"public_chat","room_version":"11","creation_content":{"m.federate":false}})")
                .body,
            "room_id");
        auto const federated = member_string(send(runtime, "POST", "/_matrix/client/v3/createRoom", alice,
                                                  R"({"preset":"public_chat","room_version":"11"})")
                                                 .body,
                                             "room_id");

        WHEN("both are upgraded")
        {
            auto const upgraded_local = send(runtime, "POST", "/_matrix/client/v3/rooms/" + local_only + "/upgrade",
                                             alice, R"({"new_version":"12"})");
            auto const upgraded_fed = send(runtime, "POST", "/_matrix/client/v3/rooms/" + federated + "/upgrade", alice,
                                           R"({"new_version":"12"})");
            REQUIRE(upgraded_local.status == 200U);
            REQUIRE(upgraded_fed.status == 200U);
            auto const local_replacement = member_string(upgraded_local.body, "replacement_room");
            auto const fed_replacement = member_string(upgraded_fed.body, "replacement_room");
            auto const local_create = parse_object(
                send(runtime, "GET", "/_matrix/client/v3/rooms/" + local_replacement + "/state/m.room.create/", alice)
                    .body);
            auto const fed_create = parse_object(
                send(runtime, "GET", "/_matrix/client/v3/rooms/" + fed_replacement + "/state/m.room.create/", alice)
                    .body);

            THEN("the replacement of the local-only room is local-only")
            {
                auto const* flag = merovingian::tests::bool_member(local_create, "m.federate");
                REQUIRE(flag != nullptr);
                REQUIRE_FALSE(*flag);
            }
            AND_THEN("the replacement of the federated room carries no m.federate key")
            {
                REQUIRE(merovingian::tests::object_member(fed_create, "m.federate") == nullptr);
            }
        }
    }
}

// ADR-0611 extended (ADR-0628): an application service asserting a server administrator does not hold the
// administrator's authority to redact another local user's event.
SCENARIO("An application service asserting an administrator cannot redact as a server administrator",
         "[gate-l][appservice][masquerade][redact]")
{
    GIVEN("a public room of bob's, an administrator who joined it, and a bridge that may assert the administrator")
    {
        auto bridge = merovingian::tests::TestAppservice{.id = "bridge", .users_regex = "@admin:example.org"};
        auto started =
            merovingian::homeserver::start_client_server(merovingian::tests::appservice_test_config({bridge}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        REQUIRE(merovingian::homeserver::bootstrap_admin_user(runtime.homeserver, "admin", std::string{password}).ok);
        auto const admin_token = login(runtime, "admin");
        auto const bob = register_and_login(runtime, "bob");
        auto const room = member_string(
            send(runtime, "POST", "/_matrix/client/v3/createRoom", bob, R"({"preset":"public_chat"})").body, "room_id");
        REQUIRE(send(runtime, "POST", "/_matrix/client/v3/join/" + room, admin_token, "{}").status == 200U);
        auto const message = send(runtime, "PUT", "/_matrix/client/v3/rooms/" + room + "/send/m.room.message/t1", bob,
                                  R"({"msgtype":"m.text","body":"hello"})");
        REQUIRE(message.status == 200U);
        auto const event_id = member_string(message.body, "event_id");
        auto const bridge_token = bridge.as_token();

        WHEN("the bridge redacts bob's event as the administrator")
        {
            auto const redact =
                send(runtime, "PUT",
                     "/_matrix/client/v3/rooms/" + room + "/redact/" + event_id + "/t2?user_id=@admin:example.org",
                     bridge_token, "{}");

            THEN("it is forbidden")
            {
                REQUIRE(redact.status == 403U);
            }
        }

        WHEN("the administrator redacts bob's event with their own session")
        {
            auto const redact = send(runtime, "PUT", "/_matrix/client/v3/rooms/" + room + "/redact/" + event_id + "/t3",
                                     admin_token, "{}");

            THEN("the administrator's authority still applies")
            {
                REQUIRE(redact.status == 200U);
            }
        }
    }
}
