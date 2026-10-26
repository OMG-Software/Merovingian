// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Open registration (security.registration.require_token=false, acknowledged by
// security.registration.allow_open_registration=true, ADR-0232) still goes
// through User-Interactive Authentication, with the single stage m.login.dummy.

#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <variant>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto open_registration_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    security.registration.enabled = true;
    security.registration.require_token = false;
    security.registration.allow_open_registration = true;
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto register_with(merovingian::homeserver::ClientServerRuntime& runtime, std::string body)
    -> merovingian::homeserver::DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/register", {}, std::move(body)});
}

// The single flow's single stage, or empty when the body is not a UIA challenge
// of exactly one one-stage flow.
[[nodiscard]] auto only_stage(merovingian::canonicaljson::Object const& body) -> std::string
{
    auto const* flows = object_member_as_array(body, "flows");
    if (flows == nullptr || flows->size() != 1U)
    {
        return {};
    }
    auto const* flow = std::get_if<merovingian::canonicaljson::Object>(&flows->front().storage());
    auto const* stages = flow == nullptr ? nullptr : object_member_as_array(*flow, "stages");
    if (stages == nullptr || stages->size() != 1U)
    {
        return {};
    }
    auto const* stage = std::get_if<std::string>(&stages->front().storage());
    return stage == nullptr ? std::string{} : *stage;
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: User-Interactive Authentication API, Dummy Auth; POST /register
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#user-interactive-authentication-api
//
// "A request to an endpoint that uses User-Interactive Authentication never
// succeeds without auth. Homeservers may allow requests that don't require auth
// by offering a stage with only the m.login.dummy auth type, but they must
// still give a 401 response to requests with no auth data."
SCENARIO("Open registration challenges a request without auth data with an m.login.dummy flow",
         "[conformance][client-server][register][open-registration]")
{
    GIVEN("a running client-server with acknowledged open registration")
    {
        auto started = merovingian::homeserver::start_client_server(open_registration_config());
        // Precondition: the server starts with acknowledged open registration.
        REQUIRE(started.started);

        WHEN("an empty registration probe is submitted")
        {
            auto const response = register_with(started.runtime, "{}");

            THEN("the response is 401 offering the single stage m.login.dummy")
            {
                // Spec MUST: "they must still give a 401 response to requests with no auth data".
                REQUIRE(response.response.status == 401U);
                auto const body = parse_object(response.response.body);
                // Spec MUST: `flows` is "Required", and the server offers "a stage with only
                // the m.login.dummy auth type".
                REQUIRE(only_stage(body) == "m.login.dummy");
                // `params` and `session` are optional ("if one is provided"); when present
                // they must have the types the AuthenticationResponse schema gives them.
                if (object_member(body, "params") != nullptr)
                {
                    // Spec MUST: `params` is a `{string: object}` map.
                    REQUIRE(object_member_as_object(body, "params") != nullptr);
                }
                if (object_member(body, "session") != nullptr)
                {
                    auto const* session = string_member(body, "session");
                    // Spec MUST: `session` is a string the client passes back.
                    REQUIRE(session != nullptr);
                    // Spec MUST: a session identifier the client can pass back is not empty.
                    REQUIRE_FALSE(session->empty());
                }
            }
        }

        WHEN("a complete username and password are submitted without an auth dict")
        {
            auto const response = register_with(started.runtime, R"({"username":"carol","password":"CorrectHorse7!"})");

            THEN("no account is created and the challenge is returned")
            {
                // Spec MUST: a UIA request "never succeeds without auth".
                REQUIRE(response.response.status == 401U);
                // Spec MUST: the 401 carries the `flows` the client must complete.
                REQUIRE(only_stage(parse_object(response.response.body)) == "m.login.dummy");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Dummy Auth
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#dummy-auth
//
// "Dummy authentication always succeeds and requires no extra parameters."
SCENARIO("Open registration completes with m.login.dummy", "[conformance][client-server][register][open-registration]")
{
    GIVEN("a running client-server with acknowledged open registration")
    {
        auto started = merovingian::homeserver::start_client_server(open_registration_config());
        // Precondition: the server starts with acknowledged open registration.
        REQUIRE(started.started);

        WHEN("a registration completes the dummy stage without a session")
        {
            auto const response = register_with(
                started.runtime, R"({"username":"carol","password":"CorrectHorse7!","auth":{"type":"m.login.dummy"}})");

            THEN("the account is created and logged in")
            {
                // Spec MUST: "Dummy authentication always succeeds".
                REQUIRE(response.response.status == 200U);
                auto const body = parse_object(response.response.body);
                auto const* user_id = string_member(body, "user_id");
                // Spec MUST: a successful registration returns the "Required" `user_id`.
                REQUIRE(user_id != nullptr);
                // Spec MUST: the user ID is built from the requested `username` localpart.
                REQUIRE(user_id->starts_with("@carol:"));
                // Spec MUST: `access_token` is "Required if the inhibit_login option is false".
                REQUIRE(string_member(body, "access_token") != nullptr);
            }
        }

        WHEN("a registration completes the dummy stage with the session its challenge issued, if any")
        {
            // A session is optional ("if one is provided"). When the challenge issues
            // one, the client passes it back; without one this case is the one above.
            auto const challenge = parse_object(register_with(started.runtime, "{}").response.body);
            auto const* session = string_member(challenge, "session");
            auto const auth = session == nullptr ? std::string{R"({"type":"m.login.dummy"})"}
                                                 : R"({"type":"m.login.dummy","session":")" + *session + R"("})";
            auto const response = register_with(
                started.runtime, R"({"username":"dave","password":"CorrectHorse7!","auth":)" + auth + "}");

            THEN("the account is created")
            {
                // Spec MUST: "Dummy authentication always succeeds".
                REQUIRE(response.response.status == 200U);
                // Spec MUST: a successful registration returns the "Required" `user_id`.
                REQUIRE(string_member(parse_object(response.response.body), "user_id") != nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: User-Interactive Authentication API
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#user-interactive-authentication-api
//
// A stage the server did not offer, or a session it did not issue, does not
// complete authentication; the server answers with the challenge again.
SCENARIO("Open registration refuses stages and sessions it did not offer",
         "[conformance][client-server][register][open-registration]")
{
    GIVEN("a running client-server with acknowledged open registration")
    {
        auto started = merovingian::homeserver::start_client_server(open_registration_config());
        // Precondition: the server starts with acknowledged open registration.
        REQUIRE(started.started);

        WHEN("the client answers with a registration-token stage instead")
        {
            auto const response =
                register_with(started.runtime, R"({"username":"erin","password":"CorrectHorse7!",)"
                                               R"("auth":{"type":"m.login.registration_token","token":"anything"}})");

            THEN("the response is the 401 dummy challenge")
            {
                // Spec MUST: authentication completes only through a stage the server offered.
                REQUIRE(response.response.status == 401U);
                // Spec MUST: the 401 repeats the `flows` the client must complete.
                REQUIRE(only_stage(parse_object(response.response.body)) == "m.login.dummy");
            }
        }

        WHEN("the client completes the dummy stage under a session the server never issued")
        {
            auto const response = register_with(
                started.runtime, R"({"username":"frank","password":"CorrectHorse7!",)"
                                 R"("auth":{"type":"m.login.dummy","session":"not-a-session-we-issued"}})");

            THEN("the response is the 401 dummy challenge and no account is created")
            {
                // Spec MUST: a `session` passes back one "the homeserver" provided, never another.
                REQUIRE(response.response.status == 401U);
                // Spec MUST: the 401 repeats the `flows` the client must complete.
                REQUIRE(only_stage(parse_object(response.response.body)) == "m.login.dummy");
            }
        }
    }
}
