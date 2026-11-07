// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"

// CS8 (ADR-0548): POST /_matrix/client/v1/login/get_token, the `m.login.token` login it feeds, the
// `m.get_login_token` capability, and GET /_matrix/client/v3/admin/whois/{userId}.
//
// Spec: Matrix Client-Server API v1.19, "POST /_matrix/client/v1/login/get_token", "Token-based login",
// "m.get_login_token capability", "User-Interactive Authentication API" and "GET /admin/whois/{userId}".
// ../../docs/matrix-v1.19-spec/client-server-api.md

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
#include "merovingian/homeserver/auth_service.hpp"

#include <catch2/catch_test_macros.hpp>
#include <sodium.h>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <vector>

namespace
{

using namespace merovingian::tests;
namespace hs = merovingian::homeserver;

constexpr auto password = "CorrectHorse7!";
constexpr auto get_token_path = "/_matrix/client/v1/login/get_token";

[[nodiscard]] auto make_config(bool login_token_enabled) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    security.login_token.enabled = login_token_enabled;
    auto server = merovingian::config::ServerConfig{};
    server.server_name = "example.org";
    return {
        server,   merovingian::config::ListenersConfig{},        merovingian::tests::in_memory_database_config(),
        security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto start(bool login_token_enabled) -> hs::ClientServerStartResult
{
    REQUIRE(sodium_init() >= 0);
    auto started = hs::start_client_server(make_config(login_token_enabled));
    REQUIRE(started.started);
    return started;
}

[[nodiscard]] auto send(hs::ClientServerRuntime& runtime, std::string method, std::string target, std::string token,
                        std::string body = {}) -> hs::LocalHttpResponse
{
    return hs::handle_client_server_request(runtime, {std::move(method), std::move(target), std::move(token),
                                                      std::move(body)})
        .response;
}

// Registers `localpart` and logs it in on `device`, returning the access token.
[[nodiscard]] auto sign_in(hs::ClientServerRuntime& runtime, std::string const& localpart, std::string const& device)
    -> std::string
{
    auto const registered = send(runtime, "POST", "/_matrix/client/v3/register", {},
                                 merovingian::tests::registration_json(localpart, password));
    REQUIRE(registered.status == 200U);
    auto const login = send(runtime, "POST", "/_matrix/client/v3/login", {},
                            R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + localpart +
                                R"(:example.org"},"password":")" + password + R"(","device_id":")" + device + R"("})");
    REQUIRE(login.status == 200U);
    auto const body = parse_object(login.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto sign_in_admin(hs::ClientServerRuntime& runtime, std::string const& localpart) -> std::string
{
    REQUIRE(hs::bootstrap_admin_user(runtime.homeserver, localpart, password).ok);
    auto const login = send(runtime, "POST", "/_matrix/client/v3/login", {},
                            R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + localpart +
                                R"(:example.org"},"password":")" + password + R"(","device_id":"ADMINDEV"})");
    REQUIRE(login.status == 200U);
    auto const body = parse_object(login.body);
    return *string_member(body, "access_token");
}

[[nodiscard]] auto password_auth(std::string_view supplied, std::string_view session = {}) -> std::string
{
    auto auth = std::string{R"({"auth":{"type":"m.login.password","password":")"} + std::string{supplied} + "\"";
    if (!session.empty())
    {
        auth += R"(,"session":")" + std::string{session} + "\"";
    }
    return auth + "}}";
}

[[nodiscard]] auto request_login_token(hs::ClientServerRuntime& runtime, std::string const& access_token,
                                       std::string_view supplied = password) -> hs::LocalHttpResponse
{
    return send(runtime, "POST", get_token_path, access_token, password_auth(supplied));
}

[[nodiscard]] auto minted_login_token(hs::ClientServerRuntime& runtime, std::string const& access_token) -> std::string
{
    auto const response = request_login_token(runtime, access_token);
    REQUIRE(response.status == 200U);
    auto const body = parse_object(response.body);
    auto const* minted = string_member(body, "login_token");
    REQUIRE(minted != nullptr);
    return *minted;
}

[[nodiscard]] auto login_with_token(hs::ClientServerRuntime& runtime, std::string const& login_token,
                                    std::string const& device) -> hs::LocalHttpResponse
{
    return send(runtime, "POST", "/_matrix/client/v3/login", {},
                R"({"type":"m.login.token","token":")" + login_token + R"(","device_id":")" + device + R"("})");
}

[[nodiscard]] auto errcode_of(hs::LocalHttpResponse const& response) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* errcode = string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

[[nodiscard]] auto has_login_token_flow(hs::LocalHttpResponse const& response) -> bool
{
    auto const body = parse_object(response.body);
    auto const* flows = object_member_as_array(body, "flows");
    REQUIRE(flows != nullptr);
    return std::ranges::any_of(*flows, [](auto const& flow) {
        auto const* object = std::get_if<merovingian::canonicaljson::Object>(&flow.storage());
        auto const* type = object == nullptr ? nullptr : string_member(*object, "type");
        return type != nullptr && *type == "m.login.token";
    });
}

[[nodiscard]] auto capability_enabled(hs::ClientServerRuntime& runtime, std::string const& access_token)
    -> std::optional<bool>
{
    auto const response = send(runtime, "GET", "/_matrix/client/v3/capabilities", access_token);
    REQUIRE(response.status == 200U);
    auto const body = parse_object(response.body);
    auto const* capabilities = object_member_as_object(body, "capabilities");
    REQUIRE(capabilities != nullptr);
    auto const* capability = object_member_as_object(*capabilities, "m.get_login_token");
    if (capability == nullptr)
    {
        return std::nullopt;
    }
    auto const* enabled = bool_member(*capability, "enabled");
    REQUIRE(enabled != nullptr);
    return *enabled;
}

} // namespace

SCENARIO("The login token feature is off by default", "[cs8][login-token][client-server]")
{
    GIVEN("a server with the default configuration and a signed-in user")
    {
        REQUIRE(merovingian::config::SecurityConfig{}.login_token.enabled == false);
        auto started = start(false);
        auto const alice = sign_in(started.runtime, "alice", "DEVICE1");

        WHEN("an authenticated user calls POST /login/get_token with the right password")
        {
            auto const response = request_login_token(started.runtime, alice);

            THEN("the endpoint is not recognised and no token is minted")
            {
                REQUIRE(response.status == 404U);
                REQUIRE(errcode_of(response) == "M_UNRECOGNIZED");
                REQUIRE(started.runtime.login_tokens.size() == 0U);
            }
        }

        WHEN("a caller with no access token calls POST /login/get_token")
        {
            auto const response = send(started.runtime, "POST", get_token_path, {}, "{}");

            THEN("it is 404 M_UNRECOGNIZED, as for any endpoint this server does not serve")
            {
                REQUIRE(response.status == 404U);
                REQUIRE(errcode_of(response) == "M_UNRECOGNIZED");
            }
        }

        WHEN("GET /login and GET /capabilities are read")
        {
            auto const flows = send(started.runtime, "GET", "/_matrix/client/v3/login", {});
            auto const capability = capability_enabled(started.runtime, alice);

            THEN("no m.login.token flow is offered and the capability reports enabled: false")
            {
                REQUIRE(flows.status == 200U);
                REQUIRE_FALSE(has_login_token_flow(flows));
                REQUIRE(capability.has_value());
                REQUIRE_FALSE(*capability);
            }
        }
    }
}

SCENARIO("An enabled server offers the m.login.token flow and capability", "[cs8][login-token][client-server]")
{
    GIVEN("a server with security.login_token.enabled and a signed-in user")
    {
        auto started = start(true);
        auto const alice = sign_in(started.runtime, "alice", "DEVICE1");

        WHEN("GET /login and GET /capabilities are read")
        {
            auto const flows = send(started.runtime, "GET", "/_matrix/client/v3/login", {});
            auto const capability = capability_enabled(started.runtime, alice);

            THEN("the m.login.token flow says get_login_token is true and the capability is enabled")
            {
                REQUIRE(flows.status == 200U);
                REQUIRE(has_login_token_flow(flows));
                auto const body = parse_object(flows.body);
                auto const* list = object_member_as_array(body, "flows");
                REQUIRE(list != nullptr);
                auto offered_get_login_token = false;
                for (auto const& flow : *list)
                {
                    auto const* object = std::get_if<merovingian::canonicaljson::Object>(&flow.storage());
                    auto const* type = object == nullptr ? nullptr : string_member(*object, "type");
                    if (type != nullptr && *type == "m.login.token")
                    {
                        auto const* get_login_token = bool_member(*object, "get_login_token");
                        offered_get_login_token = get_login_token != nullptr && *get_login_token;
                    }
                }
                REQUIRE(offered_get_login_token);
                REQUIRE(capability.has_value());
                REQUIRE(*capability);
            }
        }
    }
}

SCENARIO("get_token always asks for a fresh password", "[cs8][login-token][client-server][uia]")
{
    GIVEN("an enabled server and a signed-in user")
    {
        auto started = start(true);
        auto const alice = sign_in(started.runtime, "alice", "DEVICE1");

        WHEN("the request carries no auth")
        {
            auto const response = send(started.runtime, "POST", get_token_path, alice, "{}");

            THEN("the answer is a 401 challenge offering m.login.password with a session")
            {
                REQUIRE(response.status == 401U);
                auto const body = parse_object(response.body);
                REQUIRE(object_member_as_array(body, "flows") != nullptr);
                REQUIRE(string_member(body, "session") != nullptr);
                REQUIRE_FALSE(string_member(body, "session")->empty());
                REQUIRE(string_member(body, "login_token") == nullptr);
                REQUIRE(started.runtime.login_tokens.size() == 0U);
            }
        }

        WHEN("the password is wrong")
        {
            auto const response = request_login_token(started.runtime, alice, "not-the-password");

            THEN("the answer is 401 with M_FORBIDDEN and no token is minted")
            {
                REQUIRE(response.status == 401U);
                REQUIRE(errcode_of(response) == "M_FORBIDDEN");
                REQUIRE(started.runtime.login_tokens.size() == 0U);
            }
        }

        WHEN("the password is right")
        {
            auto const response = request_login_token(started.runtime, alice);

            THEN("a login token and its two-minute lifetime are returned")
            {
                REQUIRE(response.status == 200U);
                auto const body = parse_object(response.body);
                auto const* minted = string_member(body, "login_token");
                REQUIRE(minted != nullptr);
                REQUIRE(minted->size() >= 32U);
                auto const* expires = int_member(body, "expires_in_ms");
                REQUIRE(expires != nullptr);
                REQUIRE(*expires == 120000);
                REQUIRE(started.runtime.login_tokens.size() == 1U);
            }
        }

        WHEN("a call has just succeeded, the next call omits the password or reuses its session")
        {
            auto const first = send(started.runtime, "POST", get_token_path, alice, "{}");
            auto const session = *string_member(parse_object(first.body), "session");
            REQUIRE(send(started.runtime, "POST", get_token_path, alice, password_auth(password, session)).status ==
                    200U);
            auto const without_auth = send(started.runtime, "POST", get_token_path, alice, "{}");
            auto const session_only = send(started.runtime, "POST", get_token_path, alice,
                                           R"({"auth":{"type":"m.login.password","session":")" + session + R"("}})");

            THEN("each is challenged again; only a fresh password mints a second token")
            {
                REQUIRE(without_auth.status == 401U);
                REQUIRE(session_only.status == 401U);
                REQUIRE(started.runtime.login_tokens.size() == 1U);
                REQUIRE(request_login_token(started.runtime, alice).status == 200U);
                REQUIRE(started.runtime.login_tokens.size() == 2U);
            }
        }

        WHEN("no access token is given")
        {
            auto const response = send(started.runtime, "POST", get_token_path, {}, password_auth(password));

            THEN("the answer is 401 M_MISSING_TOKEN")
            {
                REQUIRE(response.status == 401U);
                REQUIRE(errcode_of(response) == "M_MISSING_TOKEN");
            }
        }

        WHEN("the method is not POST")
        {
            auto const response = send(started.runtime, "GET", get_token_path, alice);

            THEN("the answer is 405 M_UNRECOGNIZED")
            {
                REQUIRE(response.status == 405U);
                REQUIRE(errcode_of(response) == "M_UNRECOGNIZED");
            }
        }
    }
}

SCENARIO("A login token logs in exactly once", "[cs8][login-token][client-server]")
{
    GIVEN("an enabled server where alice has minted a login token")
    {
        auto started = start(true);
        auto const alice = sign_in(started.runtime, "alice", "DEVICE1");
        auto const minted = minted_login_token(started.runtime, alice);

        WHEN("an unauthenticated client logs in with it on a new device")
        {
            auto const response = login_with_token(started.runtime, minted, "NEWDEV");

            THEN("it gets a session for alice on that device, and the new device is listed")
            {
                REQUIRE(response.status == 200U);
                auto const body = parse_object(response.body);
                REQUIRE(*string_member(body, "user_id") == "@alice:example.org");
                REQUIRE(*string_member(body, "device_id") == "NEWDEV");
                auto const new_token = *string_member(body, "access_token");
                REQUIRE(new_token != alice);
                auto const who = send(started.runtime, "GET", "/_matrix/client/v3/account/whoami", new_token);
                REQUIRE(who.status == 200U);
                REQUIRE(*string_member(parse_object(who.body), "device_id") == "NEWDEV");
                auto const devices = send(started.runtime, "GET", "/_matrix/client/v3/devices", alice);
                REQUIRE(devices.body.find("NEWDEV") != std::string::npos);
                REQUIRE(started.runtime.login_tokens.size() == 0U);
            }
        }

        WHEN("the same token is used a second time")
        {
            REQUIRE(login_with_token(started.runtime, minted, "NEWDEV").status == 200U);
            auto const again = login_with_token(started.runtime, minted, "OTHERDEV");

            THEN("the second login is refused and creates no device")
            {
                REQUIRE(again.status == 403U);
                REQUIRE(errcode_of(again) == "M_FORBIDDEN");
                auto const devices = send(started.runtime, "GET", "/_matrix/client/v3/devices", alice);
                REQUIRE(devices.body.find("OTHERDEV") == std::string::npos);
            }
        }

        WHEN("a token nobody minted is tried")
        {
            auto const forged = login_with_token(started.runtime, std::string(minted.size(), 'a'), "FORGED");
            auto const real = login_with_token(started.runtime, minted, "NEWDEV");

            THEN("it is refused and does not use up the real token")
            {
                REQUIRE(forged.status == 403U);
                REQUIRE(real.status == 200U);
            }
        }

        WHEN("the login names another user in its body")
        {
            auto const response =
                send(started.runtime, "POST", "/_matrix/client/v3/login", {},
                     R"({"type":"m.login.token","identifier":{"type":"m.id.user","user":"@bob:example.org"},"token":")" +
                         minted + R"(","device_id":"NEWDEV"})");

            THEN("the session is still for the user the token was minted for")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(*string_member(parse_object(response.body), "user_id") == "@alice:example.org");
            }
        }
    }
}

SCENARIO("A login token expires and is spent by a failed attempt", "[cs8][login-token][client-server]")
{
    GIVEN("an enabled server whose login tokens live one millisecond")
    {
        auto started = start(true);
        started.runtime.limits.login_token_lifetime_ms = 1U;
        auto const alice = sign_in(started.runtime, "alice", "DEVICE1");
        auto const minted = minted_login_token(started.runtime, alice);

        WHEN("the token is used after its lifetime")
        {
            std::this_thread::sleep_for(std::chrono::milliseconds{30});
            auto const response = login_with_token(started.runtime, minted, "LATE");

            THEN("the login is refused and the token is gone")
            {
                REQUIRE(response.status == 403U);
                REQUIRE(errcode_of(response) == "M_FORBIDDEN");
                REQUIRE(started.runtime.login_tokens.size() == 0U);
            }
        }
    }

    GIVEN("an enabled server where alice minted a token and then her account was deactivated")
    {
        auto started = start(true);
        auto const alice = sign_in(started.runtime, "alice", "DEVICE1");
        auto const minted = minted_login_token(started.runtime, alice);
        for (auto& user : started.runtime.homeserver.database.users)
        {
            if (user.user_id == "@alice:example.org")
            {
                user.deactivated = true;
            }
        }

        WHEN("the token is used")
        {
            auto const first = login_with_token(started.runtime, minted, "AFTER");
            auto const second = login_with_token(started.runtime, minted, "AFTER");

            THEN("the login is refused and the attempt spent the token")
            {
                REQUIRE(first.status == 403U);
                REQUIRE(second.status == 403U);
                REQUIRE(started.runtime.login_tokens.size() == 0U);
            }
        }
    }

    GIVEN("an enabled server where alice minted a token and then her account was locked")
    {
        auto started = start(true);
        auto const alice = sign_in(started.runtime, "alice", "DEVICE1");
        auto const minted = minted_login_token(started.runtime, alice);
        for (auto& user : started.runtime.homeserver.database.users)
        {
            if (user.user_id == "@alice:example.org")
            {
                user.locked = true;
            }
        }

        WHEN("the token is used and, separately, the password")
        {
            auto const by_token = login_with_token(started.runtime, minted, "AFTER");
            auto const by_password =
                send(started.runtime, "POST", "/_matrix/client/v3/login", {},
                     R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":")" +
                         std::string{password} + R"(","device_id":"PWDEV"})");

            THEN("both are refused the same way")
            {
                REQUIRE(by_token.status != 200U);
                REQUIRE(by_token.status == by_password.status);
                REQUIRE(errcode_of(by_token) == errcode_of(by_password));
            }
        }
    }
}

SCENARIO("A user holds a bounded number of login tokens", "[cs8][login-token][client-server]")
{
    GIVEN("an enabled server with no HTTP rate limiting and the default per-user cap of four tokens")
    {
        auto started = start(true);
        started.runtime.rate_limit_engine.reset();
        auto const alice = sign_in(started.runtime, "alice", "DEVICE1");
        auto const bob = sign_in(started.runtime, "bob", "DEVICE1");
        auto const first = minted_login_token(started.runtime, alice);
        for (auto count = 1U; count < 4U; ++count)
        {
            std::ignore = minted_login_token(started.runtime, alice);
        }

        WHEN("alice asks for a fifth")
        {
            auto const response = request_login_token(started.runtime, alice);

            THEN("it is 429 M_LIMIT_EXCEEDED with a retry delay, and bob is not affected")
            {
                REQUIRE(response.status == 429U);
                REQUIRE(errcode_of(response) == "M_LIMIT_EXCEEDED");
                auto const* retry = int_member(parse_object(response.body), "retry_after_ms");
                REQUIRE(retry != nullptr);
                REQUIRE(*retry > 0);
                REQUIRE(started.runtime.login_tokens.count_for_user("@alice:example.org") == 4U);
                REQUIRE(request_login_token(started.runtime, bob).status == 200U);
            }
        }

        WHEN("one of alice's tokens is used")
        {
            REQUIRE(login_with_token(started.runtime, first, "NEWDEV").status == 200U);
            auto const response = request_login_token(started.runtime, alice);

            THEN("a new token can be minted")
            {
                REQUIRE(response.status == 200U);
            }
        }
    }

    GIVEN("an enabled server whose server-wide cap is two tokens")
    {
        auto started = start(true);
        started.runtime.rate_limit_engine.reset();
        started.runtime.limits.max_login_tokens = 2U;
        auto const alice = sign_in(started.runtime, "alice", "DEVICE1");
        auto const bob = sign_in(started.runtime, "bob", "DEVICE1");
        auto const carol = sign_in(started.runtime, "carol", "DEVICE1");
        std::ignore = minted_login_token(started.runtime, alice);
        std::ignore = minted_login_token(started.runtime, bob);

        WHEN("a third user asks")
        {
            auto const response = request_login_token(started.runtime, carol);

            THEN("it is 429 M_LIMIT_EXCEEDED and no token of another user was evicted")
            {
                REQUIRE(response.status == 429U);
                REQUIRE(errcode_of(response) == "M_LIMIT_EXCEEDED");
                REQUIRE(started.runtime.login_tokens.size() == 2U);
            }
        }
    }
}

SCENARIO("get_token is rate limited per user", "[cs8][login-token][client-server][rate-limit]")
{
    GIVEN("an enabled server with the built-in rate limits and a high live-token cap")
    {
        auto started = start(true);
        started.runtime.limits.max_login_tokens_per_user = 100U;
        auto const alice = sign_in(started.runtime, "alice", "DEVICE1");
        auto const bob = sign_in(started.runtime, "bob", "DEVICE1");

        WHEN("alice makes more requests than the per-minute budget allows")
        {
            auto statuses = std::vector<std::uint16_t>{};
            for (auto count = 0U; count < 6U; ++count)
            {
                statuses.push_back(request_login_token(started.runtime, alice).status);
            }

            THEN("the requests beyond the budget are 429 and mint nothing, while bob is unaffected")
            {
                REQUIRE(std::ranges::count(statuses, std::uint16_t{200U}) == 4);
                REQUIRE(std::ranges::count(statuses, std::uint16_t{429U}) == 2);
                REQUIRE(started.runtime.login_tokens.count_for_user("@alice:example.org") == 4U);
                REQUIRE(request_login_token(started.runtime, bob).status == 200U);
            }
        }
    }
}

SCENARIO("GET /admin/whois/{userId} answers the user and the server admin", "[cs8][whois][client-server]")
{
    GIVEN("an administrator, alice with a device and bob")
    {
        auto started = start(false);
        auto const admin = sign_in_admin(started.runtime, "root");
        auto const alice = sign_in(started.runtime, "alice", "ALICEDEV");
        auto const bob = sign_in(started.runtime, "bob", "BOBDEV");
        auto const whois = [&](std::string const& token, std::string const& user_id) {
            return send(started.runtime, "GET", "/_matrix/client/v3/admin/whois/" + user_id, token);
        };

        WHEN("the administrator looks up alice")
        {
            auto const response = whois(admin, "%40alice%3Aexample.org");

            THEN("the answer names alice and lists her device with a session")
            {
                REQUIRE(response.status == 200U);
                auto const body = parse_object(response.body);
                REQUIRE(*string_member(body, "user_id") == "@alice:example.org");
                auto const* devices = object_member_as_object(body, "devices");
                REQUIRE(devices != nullptr);
                REQUIRE(devices->size() == 1U);
                auto const* device = object_member_as_object(*devices, "ALICEDEV");
                REQUIRE(device != nullptr);
                auto const* sessions = object_member_as_array(*device, "sessions");
                REQUIRE(sessions != nullptr);
                REQUIRE(sessions->size() == 1U);
                // The server records no source address or user agent, so there is no connection to report.
                auto const* session = std::get_if<merovingian::canonicaljson::Object>(&sessions->front().storage());
                REQUIRE(session != nullptr);
                auto const* connections = object_member_as_array(*session, "connections");
                REQUIRE(connections != nullptr);
                REQUIRE(connections->empty());
            }
        }

        WHEN("alice looks herself up")
        {
            auto const response = whois(alice, "%40alice%3Aexample.org");

            THEN("she gets her own answer")
            {
                REQUIRE(response.status == 200U);
                REQUIRE(*string_member(parse_object(response.body), "user_id") == "@alice:example.org");
            }
        }

        WHEN("alice looks up bob")
        {
            auto const response = whois(alice, "%40bob%3Aexample.org");

            THEN("she is refused, and learns nothing about bob's devices")
            {
                REQUIRE(response.status == 403U);
                REQUIRE(errcode_of(response) == "M_FORBIDDEN");
                REQUIRE(response.body.find("BOBDEV") == std::string::npos);
            }
        }

        WHEN("alice looks up a user that does not exist, and a user on another server")
        {
            auto const unknown = whois(alice, "%40nobody%3Aexample.org");
            auto const remote = whois(alice, "%40bob%3Aelsewhere.example");

            THEN("both are refused alike, so a non-admin cannot probe for accounts")
            {
                REQUIRE(unknown.status == 403U);
                REQUIRE(remote.status == 403U);
            }
        }

        WHEN("the administrator looks up an unknown local user, a remote user and a malformed id")
        {
            auto const unknown = whois(admin, "%40nobody%3Aexample.org");
            auto const remote = whois(admin, "%40bob%3Aelsewhere.example");
            auto const malformed = whois(admin, "not-a-user-id");

            THEN("they are 404 M_NOT_FOUND, 400 M_INVALID_PARAM and 400 M_INVALID_PARAM")
            {
                REQUIRE(unknown.status == 404U);
                REQUIRE(errcode_of(unknown) == "M_NOT_FOUND");
                REQUIRE(remote.status == 400U);
                REQUIRE(errcode_of(remote) == "M_INVALID_PARAM");
                REQUIRE(malformed.status == 400U);
                REQUIRE(errcode_of(malformed) == "M_INVALID_PARAM");
            }
        }

        WHEN("no access token is given")
        {
            auto const response = whois({}, "%40alice%3Aexample.org");

            THEN("the answer is 401 M_MISSING_TOKEN")
            {
                REQUIRE(response.status == 401U);
                REQUIRE(errcode_of(response) == "M_MISSING_TOKEN");
            }
        }

        WHEN("the method is not GET")
        {
            auto const response =
                send(started.runtime, "POST", "/_matrix/client/v3/admin/whois/%40alice%3Aexample.org", admin);

            THEN("the answer is 405 M_UNRECOGNIZED")
            {
                REQUIRE(response.status == 405U);
                REQUIRE(errcode_of(response) == "M_UNRECOGNIZED");
            }
        }
    }
}
