// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/InMemoryDatabaseConfig.hpp"

// C45 (ADR-0683): the pool of User-Interactive Authentication sessions is shared, so one owner's challenges neither
// evict another owner's live session nor let a session be used by anyone but the account it was issued to.
//
// Spec: Matrix Client-Server API v1.19, "User-Interactive Authentication API" (the `session` a client echoes back is
// the server's handle on one attempt) and "POST /delete_devices".
// ../../docs/matrix-v1.19-spec/client-server-api.md

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
#include <sodium.h>

#include <cstdint>
#include <string>
#include <tuple>
#include <utility>

namespace
{

using namespace merovingian::tests;
namespace hs = merovingian::homeserver;

constexpr auto password = "CorrectHorse7!";
constexpr auto delete_devices_path = "/_matrix/client/v3/delete_devices";

[[nodiscard]] auto make_config(std::uint32_t pool_size) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    auto server = merovingian::config::ServerConfig{};
    server.server_name = "example.org";
    server.client_api.max_uia_sessions = pool_size;
    return {
        server,   merovingian::config::ListenersConfig{},        merovingian::tests::in_memory_database_config(),
        security, merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto send(hs::ClientServerRuntime& runtime, std::string method, std::string target, std::string token,
                        std::string body = {}) -> hs::LocalHttpResponse
{
    return hs::handle_client_server_request(runtime,
                                            {std::move(method), std::move(target), std::move(token), std::move(body)})
        .response;
}

[[nodiscard]] auto login(hs::ClientServerRuntime& runtime, std::string const& localpart, std::string const& device)
    -> std::string
{
    auto const response =
        send(runtime, "POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + localpart +
                 R"(:example.org"},"password":")" + password + R"(","device_id":")" + device + R"("})");
    REQUIRE(response.status == 200U);
    auto const body = parse_object(response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

// Registers `localpart` and gives it a second device `<localpart>2` to delete. Returns the first device's token.
[[nodiscard]] auto account_with_two_devices(hs::ClientServerRuntime& runtime, std::string const& localpart)
    -> std::string
{
    REQUIRE(send(runtime, "POST", "/_matrix/client/v3/register", {},
                 merovingian::tests::registration_json(localpart, password))
                .status == 200U);
    auto const token = login(runtime, localpart, localpart + "1");
    std::ignore = login(runtime, localpart, localpart + "2");
    return token;
}

// A challenge-provoking request: no auth block, so the server answers 401 and mints a session.
[[nodiscard]] auto challenge(hs::ClientServerRuntime& runtime, std::string const& token, std::string const& device)
    -> hs::LocalHttpResponse
{
    return send(runtime, "POST", delete_devices_path, token, R"({"devices":[")" + device + R"("]})");
}

[[nodiscard]] auto session_of(hs::LocalHttpResponse const& response) -> std::string
{
    REQUIRE(response.status == 401U);
    auto const body = parse_object(response.body);
    auto const* session = string_member(body, "session");
    REQUIRE(session != nullptr);
    return *session;
}

[[nodiscard]] auto answer(hs::ClientServerRuntime& runtime, std::string const& token, std::string const& device,
                          std::string const& session) -> hs::LocalHttpResponse
{
    return send(runtime, "POST", delete_devices_path, token,
                R"({"devices":[")" + device + R"("],"auth":{"type":"m.login.password","password":")" + password +
                    R"(","session":")" + session + R"("}})");
}

} // namespace

SCENARIO("One user's challenge flood does not void another user's UIA session", "[uia][c45][integration]")
{
    GIVEN("a pool of twenty sessions, a victim holding a challenge and an attacker with a device to delete")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_client_server(make_config(20U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const victim = account_with_two_devices(runtime, "victim");
        auto const attacker = account_with_two_devices(runtime, "attacker");
        auto const victim_session = session_of(challenge(runtime, victim, "victim2"));

        WHEN("the attacker provokes thirty challenges and the victim then answers theirs")
        {
            for (auto count = 0; count < 30; ++count)
            {
                REQUIRE(challenge(runtime, attacker, "attacker2").status == 401U);
            }
            auto const answered = answer(runtime, victim, "victim2", victim_session);

            THEN("the victim's session still completes the deletion")
            {
                REQUIRE(answered.status == 200U);
            }
        }

        WHEN("the attacker answers with the victim's session")
        {
            auto const answered = answer(runtime, attacker, "attacker2", victim_session);

            THEN("the session is not accepted for another account")
            {
                REQUIRE(answered.status == 401U);
                REQUIRE(answer(runtime, victim, "victim2", victim_session).status == 200U);
            }
        }
    }
}

SCENARIO("A full UIA pool refuses a new challenge and keeps the live ones", "[uia][c45][integration]")
{
    GIVEN("a pool of three sessions held by three users")
    {
        REQUIRE(sodium_init() >= 0);
        auto started = hs::start_client_server(make_config(3U));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const first = account_with_two_devices(runtime, "first");
        auto const second = account_with_two_devices(runtime, "second");
        auto const third = account_with_two_devices(runtime, "third");
        auto const fourth = account_with_two_devices(runtime, "fourth");
        auto const first_session = session_of(challenge(runtime, first, "first2"));
        std::ignore = session_of(challenge(runtime, second, "second2"));
        std::ignore = session_of(challenge(runtime, third, "third2"));

        WHEN("a fourth user asks for a challenge")
        {
            auto const refused = challenge(runtime, fourth, "fourth2");

            THEN("it is answered 429 M_LIMIT_EXCEEDED and the first user's session still completes")
            {
                REQUIRE(refused.status == 429U);
                auto const body = parse_object(refused.body);
                REQUIRE(*string_member(body, "errcode") == "M_LIMIT_EXCEEDED");
                REQUIRE(answer(runtime, first, "first2", first_session).status == 200U);
            }
        }
    }
}
