// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |         MATRIX PASSWORD RESET BY EMAIL CONFORMANCE TESTS                 |
// |                                                                          |
// |  Spec: Matrix Client-Server API v1.19                                     |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md                  |
// |                                                                          |
// |  Covers POST /account/password/{email,msisdn}/requestToken and           |
// |  POST /account/password with m.login.email.identity. The emailed code    |
// |  itself is exercised against a mock relay in the integration suite.      |
// +-------------------------------------------------------------------------+

#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/database/PersistentStore.hpp"
#include "merovingian/database/PersistentThreePidBinding.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <optional>
#include <string>
#include <string_view>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::DispatchResult;
using merovingian::homeserver::RegistrationValidationSession;

[[nodiscard]] auto conformance_config(bool login_token_enabled = false) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    security.login_token.enabled = login_token_enabled;
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

// A relay that nothing listens on: the code is queued for it and the send fails in the background.
auto enable_email(merovingian::homeserver::ClientServerRuntime& runtime) -> void
{
    auto& email = runtime.homeserver.config.server().email;
    email.smtp_url = "smtp://127.0.0.1:1";
    email.require_tls = false;
    email.from = "matrix@example.org";
}

auto register_alice_with_email(merovingian::homeserver::ClientServerRuntime& runtime) -> void
{
    REQUIRE(merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/register",
                          {},
                          merovingian::tests::registration_json("alice", "CorrectHorse7!")})
                .response.status == 200U);
    auto binding = merovingian::database::PersistentThreePidBinding{};
    binding.user_id = "@alice:example.org";
    binding.medium = "email";
    binding.address = "alice@example.net";
    binding.added_at_ms = 1700000000000U;
    binding.validated_at_ms = 1700000000000U;
    REQUIRE(merovingian::database::store_account_threepid(runtime.homeserver.database.persistent_store, binding));
}

[[nodiscard]] auto request_token(merovingian::homeserver::ClientServerRuntime& runtime, std::string const& email,
                                 std::string const& secret, int attempt) -> DispatchResult
{
    return merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/account/password/email/requestToken",
                  {},
                  R"({"client_secret":")" + secret + R"(","email":")" + email + R"(","send_attempt":)" +
                      std::to_string(attempt) + "}"});
}

[[nodiscard]] auto errcode_of(DispatchResult const& result) -> std::string
{
    auto const body = parse_object(result.response.body);
    auto const* errcode = string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

[[nodiscard]] auto sid_of(DispatchResult const& result) -> std::string
{
    auto const body = parse_object(result.response.body);
    auto const* sid = string_member(body, "sid");
    return sid == nullptr ? std::string{} : *sid;
}

} // namespace

// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3accountpasswordemailrequesttoken
// "M_THREEPID_NOT_FOUND may be returned if no account matching the given email address could be found" (may,
// not must); "M_THREEPID_IN_USE may not be returned"; 200 carries `sid` (and `submit_url` when the homeserver
// wants the client to submit the token); "Requires authentication: No".
// Endpoint / Section: POST /_matrix/client/v3/account/password/email/requestToken
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3accountpasswordemailrequesttoken
//
// The token goes to an address "associated with an account on this homeserver". A bind at an identity
// server takes only an access token, so it is not that association (audit run 4, F-02): otherwise a
// stolen access token could bind the thief's address and then reset the password with it.
SCENARIO("A password reset is not offered for an address that was only bound at an identity server",
         "[conformance][client-server][auth][password-reset][security][f02]")
{
    GIVEN("a server that can send email and an account whose address was only bound at an identity server")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        enable_email(runtime);
        register_alice_with_email(runtime);

        auto bound_only = merovingian::database::PersistentThreePidBinding{};
        bound_only.user_id = "@alice:example.org";
        bound_only.medium = "email";
        bound_only.address = "thief@example.net";
        bound_only.id_server = "is.example.net";
        bound_only.validated_at_ms = 1700000000000U;
        bound_only.bound = true;
        REQUIRE(
            merovingian::database::store_account_threepid(runtime.homeserver.database.persistent_store, bound_only));

        auto const session_for = [&runtime](std::string_view address) -> RegistrationValidationSession const& {
            auto const found = std::ranges::find_if(runtime.registration_validation_sessions,
                                                    [address](RegistrationValidationSession const& session) {
                                                        return session.address == address;
                                                    });
            REQUIRE(found != runtime.registration_validation_sessions.end());
            return *found;
        };

        WHEN("a reset is requested for that address and for the account's own address")
        {
            auto const thief = request_token(runtime, "thief@example.net", "secret_one", 1);
            auto const owner = request_token(runtime, "alice@example.net", "secret_two", 1);

            THEN("both are answered alike, but only the account's own address is tied to the account")
            {
                // Spec: the answer must not reveal whether an address has an account.
                REQUIRE(thief.response.status == 200U);
                REQUIRE(owner.response.status == 200U);
                REQUIRE_FALSE(session_for("thief@example.net").user_id.has_value());
                REQUIRE(session_for("alice@example.net").user_id == std::optional<std::string>{"@alice:example.org"});
            }
        }

        WHEN("a validated reset session names the account, but the address was only bound")
        {
            auto const sid = sid_of(request_token(runtime, "thief@example.net", "secret_one", 1));
            auto& session = runtime.registration_validation_sessions.front();
            session.user_id = "@alice:example.org";
            session.validated_at_ms = 1700000000000U;

            auto const result = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/account/password",
                 {},
                 R"({"new_password":"BrandNewPass9!","auth":{"type":"m.login.email.identity","threepid_creds":{"sid":")" +
                     sid + R"(","client_secret":"secret_one"}}})"});

            THEN("the password is not reset")
            {
                REQUIRE(result.response.status == 401U);
                REQUIRE(errcode_of(result) == "M_SESSION_NOT_VALIDATED");
            }
        }
    }
}

// Endpoint / Section: POST /_matrix/client/v3/account/password/email/requestToken
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3accountpasswordemailrequesttoken
SCENARIO("POST /account/password/email/requestToken answers alike for an address with an account and one without",
         "[conformance][client-server][auth][password-reset]")
{
    GIVEN("a server that can send email and an account that holds alice@example.net")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        enable_email(runtime);
        register_alice_with_email(runtime);

        WHEN("a token is requested, with no access token, for the address and for one no account holds")
        {
            auto const known = request_token(runtime, "alice@example.net", "secret_one", 1);
            auto const unknown = request_token(runtime, "nobody@example.net", "secret_two", 1);

            THEN("both are 200 with a sid and a submit_url, so the answer reveals nothing about accounts")
            {
                REQUIRE(known.response.status == 200U);
                REQUIRE(unknown.response.status == 200U);
                for (auto const* result : {&known, &unknown})
                {
                    auto const body = parse_object(result->response.body);
                    REQUIRE(string_member(body, "sid") != nullptr);
                    REQUIRE(string_member(body, "submit_url") != nullptr);
                    REQUIRE(body.size() == 2U);
                }
                REQUIRE(sid_of(known) != sid_of(unknown));
            }
        }

        WHEN("the same request is repeated with the same and then a higher send_attempt")
        {
            auto const first = request_token(runtime, "alice@example.net", "secret_one", 1);
            auto const repeated = request_token(runtime, "alice@example.net", "secret_one", 1);
            auto const resent = request_token(runtime, "alice@example.net", "secret_one", 2);

            THEN("each answers 200 for the same session")
            {
                // Spec: "If they do not [increment send_attempt], the server should respond with success but not
                // resend the email."
                REQUIRE(repeated.response.status == 200U);
                REQUIRE(sid_of(repeated) == sid_of(first));
                REQUIRE(resent.response.status == 200U);
                REQUIRE(sid_of(resent) == sid_of(first));
            }
        }

        WHEN("the body is malformed or the address is not an address")
        {
            auto const no_body = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/account/password/email/requestToken", {}, "{}"});
            auto const bad_secret = request_token(runtime, "alice@example.net", "not valid!", 1);
            auto const bad_email = request_token(runtime, "not-an-address", "secret_one", 1);

            THEN("each is 400 M_BAD_JSON")
            {
                for (auto const* result : {&no_body, &bad_secret, &bad_email})
                {
                    REQUIRE(result->response.status == 400U);
                    REQUIRE(errcode_of(*result) == "M_BAD_JSON");
                }
            }
        }
    }

    GIVEN("a server with no way to send email")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a token is requested")
        {
            auto const result = request_token(runtime, "alice@example.net", "secret_one", 1);

            THEN("the answer is 400 M_THREEPID_MEDIUM_NOT_SUPPORTED, the same for every address")
            {
                REQUIRE(result.response.status == 400U);
                REQUIRE(errcode_of(result) == "M_THREEPID_MEDIUM_NOT_SUPPORTED");
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3accountpasswordmsisdnrequesttoken
// Same endpoint family; M_THREEPID_MEDIUM_NOT_SUPPORTED is the CS API errcode for a medium the homeserver does
// not support. This server has no SMS.
SCENARIO("POST /account/password/msisdn/requestToken answers that the medium is not supported",
         "[conformance][client-server][auth][password-reset]")
{
    GIVEN("a running server")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("a token is requested for a phone number, with no access token")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/account/password/msisdn/requestToken",
                 {},
                 R"({"client_secret":"secret_one","country":"GB","phone_number":"07700900000","send_attempt":1})"});

            THEN("the answer is 400 M_THREEPID_MEDIUM_NOT_SUPPORTED")
            {
                REQUIRE(result.response.status == 400U);
                REQUIRE(errcode_of(result) == "M_THREEPID_MEDIUM_NOT_SUPPORTED");
            }
        }

        WHEN("the body is malformed")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/account/password/msisdn/requestToken", {}, "{}"});

            THEN("the answer is 400 M_BAD_JSON")
            {
                REQUIRE(result.response.status == 400U);
                REQUIRE(errcode_of(result) == "M_BAD_JSON");
            }
        }
    }
}

// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#user-interactive-authentication-api
// `m.login.email.identity`: "the client should authenticate with an identity server (or homeserver). After
// authenticating, the session information should be submitted to the homeserver" as `threepid_creds`. A failed
// stage is 401 with the flows. POST /account/password: "logout_devices ... defaults to true".
SCENARIO("POST /account/password with m.login.email.identity does not reset a password for an unvalidated session",
         "[conformance][client-server][auth][password-reset]")
{
    GIVEN("an account that holds an email address and a password-reset session that nobody validated")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        enable_email(runtime);
        register_alice_with_email(runtime);
        auto const sid = sid_of(request_token(runtime, "alice@example.net", "secret_one", 1));

        WHEN("a client with no access token asks for a reset without an auth block")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/account/password", {}, R"({"new_password":"BrandNewPass9!"})"});

            THEN("the answer is the 401 challenge naming the m.login.email.identity stage")
            {
                REQUIRE(result.response.status == 401U);
                REQUIRE(result.response.body.find("m.login.email.identity") != std::string::npos);
            }
        }

        WHEN("it names the session but the code was never submitted")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"POST",
                 "/_matrix/client/v3/account/password",
                 {},
                 R"({"new_password":"BrandNewPass9!","auth":{"type":"m.login.email.identity","threepid_creds":{"sid":")" +
                     sid + R"(","client_secret":"secret_one"}}})"});

            THEN("the answer is 401 and the old password still logs in")
            {
                REQUIRE(result.response.status == 401U);
                auto const login = merovingian::homeserver::handle_client_server_request(
                    runtime,
                    {"POST",
                     "/_matrix/client/v3/login",
                     {},
                     R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"D"})"});
                REQUIRE(login.response.status == 200U);
            }
        }

        WHEN("a wrong code is submitted to the session")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/unstable/org.merovingian/account/password/email/submitToken",
                          {},
                          R"({"sid":")" + sid + R"(","client_secret":"secret_one","token":"AAAAAAAA"})"});

            THEN("the answer is 400 M_TOKEN_INCORRECT")
            {
                REQUIRE(result.response.status == 400U);
                REQUIRE(errcode_of(result) == "M_TOKEN_INCORRECT");
            }
        }

        WHEN("wrong codes are submitted past the cap")
        {
            auto last = DispatchResult{};
            for (auto attempt = 0; attempt < 6; ++attempt)
            {
                last = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST",
                              "/_matrix/client/unstable/org.merovingian/account/password/email/submitToken",
                              {},
                              R"({"sid":")" + sid + R"(","client_secret":"secret_one","token":"AAAAAAAA"})"});
            }

            THEN("the session is gone: M_SESSION_EXPIRED")
            {
                REQUIRE(last.response.status == 400U);
                REQUIRE(errcode_of(last) == "M_SESSION_EXPIRED");
            }
        }

        WHEN("the code is submitted for a session that does not exist")
        {
            auto const result = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/unstable/org.merovingian/account/password/email/submitToken",
                          {},
                          R"({"sid":"nosuchsession","client_secret":"secret_one","token":"AAAAAAAA"})"});

            THEN("the answer is 400 M_SESSION_EXPIRED")
            {
                REQUIRE(result.response.status == 400U);
                REQUIRE(errcode_of(result) == "M_SESSION_EXPIRED");
            }
        }
    }
}

// F-07 (security audit run 4): a login token comes from a session, so completing a password reset by email that
// revokes every session erases the account's unredeemed login tokens too.
// Spec: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3accountpassword ("logout_devices":
// the server revokes the access tokens of all the user's devices when true) and "POST /login/get_token".
SCENARIO("Completing a password reset by email erases the account's unredeemed login tokens",
         "[conformance][client-server][auth][password-reset][security][f07]")
{
    GIVEN("an account with an email address, a login token minted on one of its sessions and a validated reset session")
    {
        auto started = merovingian::homeserver::start_client_server(conformance_config(true));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        enable_email(runtime);
        register_alice_with_email(runtime);

        auto const login = merovingian::homeserver::handle_client_server_request(
            runtime,
            {"POST",
             "/_matrix/client/v3/login",
             {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@alice:example.org"},"password":"CorrectHorse7!","device_id":"D"})"});
        REQUIRE(login.response.status == 200U);
        auto const login_body = parse_object(login.response.body);
        auto const* const access_token = string_member(login_body, "access_token");
        REQUIRE(access_token != nullptr);
        auto const minted = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v1/login/get_token", *access_token,
                      R"({"auth":{"type":"m.login.password","password":"CorrectHorse7!"}})"});
        REQUIRE(minted.response.status == 200U);
        auto const minted_body = parse_object(minted.response.body);
        auto const* const login_token = string_member(minted_body, "login_token");
        REQUIRE(login_token != nullptr);
        auto const token_login_status = [&runtime, login_token] {
            return merovingian::homeserver::handle_client_server_request(
                       runtime, {"POST",
                                 "/_matrix/client/v3/login",
                                 {},
                                 R"({"type":"m.login.token","token":")" + *login_token + R"(","device_id":"E"})"})
                .response.status;
        };

        auto const sid = sid_of(request_token(runtime, "alice@example.net", "secret_one", 1));
        auto& session = runtime.registration_validation_sessions.front();
        session.validated_at_ms = session.updated_at_ms;
        REQUIRE(session.user_id == std::optional<std::string>{"@alice:example.org"});

        auto const complete = [&](std::string_view logout_member) {
            return merovingian::homeserver::handle_client_server_request(
                runtime, {"POST",
                          "/_matrix/client/v3/account/password",
                          {},
                          R"({"new_password":"BrandNewPass9!",)" + std::string{logout_member} +
                              R"("auth":{"type":"m.login.email.identity","threepid_creds":{"sid":")" + sid +
                              R"(","client_secret":"secret_one"}}})"});
        };

        WHEN("the reset is completed with logout_devices true")
        {
            REQUIRE(complete(R"("logout_devices":true,)").response.status == 200U);

            THEN("the token minted before the reset is refused")
            {
                // Spec MUST: logout_devices true revokes every session; a credential derived from one goes too.
                REQUIRE(token_login_status() == 403U);
            }
        }

        WHEN("the reset is completed with logout_devices false")
        {
            REQUIRE(complete(R"("logout_devices":false,)").response.status == 200U);

            THEN("the token minted before the reset still logs in")
            {
                // Spec: logout_devices false leaves the other sessions, and what came from them, alone.
                REQUIRE(token_login_status() == 200U);
            }
        }
    }
}
