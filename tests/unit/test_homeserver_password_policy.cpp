// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// security.password_policy (ADR-0236) reaches registration and password
// changes: the server applies the configured policy, not a built-in one.

#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto open_registration_config(merovingian::config::PasswordPolicyConfig policy)
    -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    security.registration.enabled = true;
    security.registration.require_token = false;
    security.registration.allow_open_registration = true;
    security.password_policy = policy;
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto register_dummy(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& username,
                                  std::string const& password) -> merovingian::homeserver::DispatchResult
{
    // The dummy stage completes only within a session the server issued, so ask for one first.
    auto const challenge = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/register", {}, "{}"});
    auto const challenge_body = merovingian::tests::parse_object(challenge.response.body);
    auto const* session = merovingian::tests::string_member(challenge_body, "session");
    REQUIRE(session != nullptr);
    return merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/register",
                  {},
                  R"({"username":")" + username + R"(","password":")" + password +
                      R"(","auth":{"type":"m.login.dummy","session":")" + *session + R"("}})"});
}

} // namespace

SCENARIO("Registration applies the configured password policy", "[homeserver][register][password-policy]")
{
    GIVEN("a server whose policy needs no character classes and one byte")
    {
        auto started = merovingian::homeserver::start_client_server(
            open_registration_config({.min_length = 1U, .require_character_classes = false}));
        REQUIRE(started.started);

        WHEN("a user registers with a six-byte lower-case password")
        {
            auto const response = register_dummy(started.runtime, "carol", "secret");

            THEN("the account is created")
            {
                REQUIRE(response.response.status == 200U);
                REQUIRE(string_member(parse_object(response.response.body), "user_id") != nullptr);
            }
        }
    }

    GIVEN("a server with the default policy")
    {
        auto started = merovingian::homeserver::start_client_server(open_registration_config({}));
        REQUIRE(started.started);

        WHEN("the same password is used")
        {
            auto const response = register_dummy(started.runtime, "carol", "secret");

            THEN("it is refused as a weak password")
            {
                REQUIRE(response.response.status == 400U);
                REQUIRE(*string_member(parse_object(response.response.body), "errcode") == "M_WEAK_PASSWORD");
            }
        }
    }

    GIVEN("a server whose policy needs sixteen bytes")
    {
        auto started = merovingian::homeserver::start_client_server(
            open_registration_config({.min_length = 16U, .require_character_classes = true}));
        REQUIRE(started.started);

        WHEN("a password that meets the default policy but is shorter is used")
        {
            auto const response = register_dummy(started.runtime, "carol", "CorrectHorse7!");

            THEN("the stricter configured minimum refuses it")
            {
                REQUIRE(response.response.status == 400U);
                REQUIRE(*string_member(parse_object(response.response.body), "errcode") == "M_WEAK_PASSWORD");
            }
        }
    }
}

// The spec lets a server reject a weak password ("Servers MAY reject weak
// passwords with an error code M_WEAK_PASSWORD"); this server does, on a
// password change as well as at registration.
SCENARIO("A password change applies the configured password policy", "[homeserver][account][password-policy]")
{
    GIVEN("a server with the default policy and a user registered with a strong password")
    {
        auto started = merovingian::homeserver::start_client_server(open_registration_config({}));
        REQUIRE(started.started);
        auto const registered = register_dummy(started.runtime, "dave", "CorrectHorse7!");
        REQUIRE(registered.response.status == 200U);
        auto const registered_body = parse_object(registered.response.body);
        auto const user_id = std::string{*string_member(registered_body, "user_id")};
        auto const token = std::string{*string_member(registered_body, "access_token")};

        WHEN("the user completes authentication and asks for a weak password")
        {
            auto const change = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/account/password", token,
                                  R"({"auth":{"type":"m.login.password","identifier":{"type":"m.id.user","user":")" +
                                      user_id + R"("},"password":"CorrectHorse7!"},"new_password":"password"})"});

            THEN("the change is refused as a weak password and the old password still logs in")
            {
                REQUIRE(change.response.status == 400U);
                auto const change_body = parse_object(change.response.body);
                REQUIRE(*string_member(change_body, "errcode") == "M_WEAK_PASSWORD");
                auto const login = merovingian::homeserver::handle_client_server_request(
                    started.runtime, {"POST",
                                      "/_matrix/client/v3/login",
                                      {},
                                      R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":")" +
                                          user_id + R"("},"password":"CorrectHorse7!"})"});
                REQUIRE(login.response.status == 200U);
            }
        }
    }
}
