// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

// Complement run 10 findings on account lifecycle and request errors: the User-Interactive
// Authentication failure body, logout deleting the device, M_MISSING_TOKEN on logout,
// registration sessions and username checks, M_NOT_JSON, and 405 M_UNRECOGNIZED.

#include "../support/in_memory_database_config.hpp"
#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace
{

using namespace merovingian::tests;
using merovingian::homeserver::ClientServerRuntime;
using merovingian::homeserver::handle_client_server_request;

[[nodiscard]] auto make_config(bool open_registration) -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    if (open_registration)
    {
        security.registration.enabled = true;
        security.registration.require_token = false;
        security.registration.allow_open_registration = true;
    }
    else
    {
        merovingian::tests::enable_token_registration(security);
    }
    security.federation.enabled = true;
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
    };
}

constexpr auto password = std::string_view{"CorrectHorse7!"};

[[nodiscard]] auto send(ClientServerRuntime& runtime, std::string method, std::string target, std::string token = {},
                        std::string body = {}) -> merovingian::homeserver::LocalHttpResponse
{
    return handle_client_server_request(runtime,
                                        {std::move(method), std::move(target), std::move(token), std::move(body)})
        .response;
}

[[nodiscard]] auto errcode_of(merovingian::homeserver::LocalHttpResponse const& response) -> std::string
{
    auto const body = parse_object(response.body);
    auto const* errcode = string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

// Registers `localpart` through the registration-token flow and logs it in under `device_id`.
[[nodiscard]] auto register_and_login(ClientServerRuntime& runtime, std::string const& localpart,
                                      std::string const& device_id) -> std::string
{
    REQUIRE(send(runtime, "POST", "/_matrix/client/v3/register", {}, registration_json(localpart, password)).status ==
            200U);
    auto const login =
        send(runtime, "POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + localpart +
                 R"(:example.org"},"password":")" + std::string{password} + R"(","device_id":")" + device_id + R"("})");
    REQUIRE(login.status == 200U);
    auto const body = parse_object(login.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto login_again(ClientServerRuntime& runtime, std::string const& localpart, std::string const& device_id)
    -> std::string
{
    auto const login =
        send(runtime, "POST", "/_matrix/client/v3/login", {},
             R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)" + localpart +
                 R"(:example.org"},"password":")" + std::string{password} + R"(","device_id":")" + device_id + R"("})");
    REQUIRE(login.status == 200U);
    auto const body = parse_object(login.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    return *token;
}

[[nodiscard]] auto device_ids(ClientServerRuntime& runtime, std::string const& token) -> std::vector<std::string>
{
    auto const response = send(runtime, "GET", "/_matrix/client/v3/devices", token);
    REQUIRE(response.status == 200U);
    auto const body = parse_object(response.body);
    auto const* devices = object_member_as_array(body, "devices");
    REQUIRE(devices != nullptr);
    auto ids = std::vector<std::string>{};
    for (auto const& entry : *devices)
    {
        auto const* device = std::get_if<merovingian::canonicaljson::Object>(&entry.storage());
        REQUIRE(device != nullptr);
        auto const* id = string_member(*device, "device_id");
        REQUIRE(id != nullptr);
        ids.push_back(*id);
    }
    return ids;
}

[[nodiscard]] auto contains(std::vector<std::string> const& ids, std::string_view id) -> bool
{
    return std::ranges::find(ids, id) != ids.end();
}

[[nodiscard]] auto password_auth(std::string_view user, std::string_view wrong_password) -> std::string
{
    return R"("auth":{"type":"m.login.password","identifier":{"type":"m.id.user","user":")" + std::string{user} +
           R"("},"password":")" + std::string{wrong_password} + R"("})";
}

} // namespace

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: User-Interactive Authentication API
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#user-interactive-authentication-api
//
// "If the homeserver decides that an attempt on a stage was unsuccessful, but the client may
// make a second attempt, it returns the same HTTP status 401 response as above, with the
// addition of the standard `errcode` and `error` fields describing the error."
SCENARIO("A failed User-Interactive Authentication stage answers 401 with errcode and error",
         "[conformance][client-server][auth][uia]")
{
    GIVEN("a registered user with a session")
    {
        auto started = merovingian::homeserver::start_client_server(make_config(false));
        REQUIRE(started.started);
        auto const token = register_and_login(started.runtime, "alice", "DEVICE1");

        auto const check_failure = [](merovingian::homeserver::LocalHttpResponse const& response) {
            // Spec MUST: the status stays 401 so the client may make a second attempt.
            REQUIRE(response.status == 401U);
            auto const body = parse_object(response.body);
            // Spec MUST: the standard `errcode` and `error` fields are added.
            REQUIRE(string_member(body, "errcode") != nullptr);
            REQUIRE(*string_member(body, "errcode") == "M_FORBIDDEN");
            REQUIRE(string_member(body, "error") != nullptr);
            // Spec MUST: the response is otherwise "the same" object, with its flows and session.
            REQUIRE(object_member_as_array(body, "flows") != nullptr);
            REQUIRE(string_member(body, "session") != nullptr);
        };

        WHEN("the wrong password is given to POST /account/deactivate")
        {
            auto const response = send(started.runtime, "POST", "/_matrix/client/v3/account/deactivate", token,
                                       "{" + password_auth("alice", "WrongHorse7!") + "}");
            THEN("the failure carries errcode M_FORBIDDEN and error")
            {
                check_failure(response);
            }
        }
        WHEN("the wrong password is given to DELETE /devices/{deviceId}")
        {
            auto const response = send(started.runtime, "DELETE", "/_matrix/client/v3/devices/DEVICE1", token,
                                       "{" + password_auth("alice", "WrongHorse7!") + "}");
            THEN("the failure carries errcode M_FORBIDDEN and error")
            {
                check_failure(response);
            }
        }
        WHEN("the wrong password is given to POST /delete_devices")
        {
            auto const response = send(started.runtime, "POST", "/_matrix/client/v3/delete_devices", token,
                                       R"({"devices":["DEVICE1"],)" + password_auth("alice", "WrongHorse7!") + "}");
            THEN("the failure carries errcode M_FORBIDDEN and error")
            {
                check_failure(response);
            }
        }
        WHEN("the wrong password is given to POST /account/password")
        {
            auto const response =
                send(started.runtime, "POST", "/_matrix/client/v3/account/password", token,
                     R"({"new_password":"AnotherHorse8!",)" + password_auth("alice", "WrongHorse7!") + "}");
            THEN("the failure carries errcode M_FORBIDDEN and error")
            {
                check_failure(response);
            }
        }
        WHEN("the wrong password is given to POST /keys/device_signing/upload")
        {
            auto const response = send(started.runtime, "POST", "/_matrix/client/v3/keys/device_signing/upload", token,
                                       "{" + password_auth("alice", "WrongHorse7!") + "}");
            THEN("the failure carries errcode M_FORBIDDEN and error")
            {
                check_failure(response);
            }
        }
        WHEN("no auth dict is given to POST /account/deactivate")
        {
            auto const response = send(started.runtime, "POST", "/_matrix/client/v3/account/deactivate", token, "{}");
            THEN("the challenge is the same object without an attempt, so it has no errcode")
            {
                // Spec: an unauthenticated request gets flows/params/session; errcode and
                // error describe a failed attempt, and there was none.
                REQUIRE(response.status == 401U);
                auto const body = parse_object(response.body);
                REQUIRE(string_member(body, "errcode") == nullptr);
                REQUIRE(object_member_as_array(body, "flows") != nullptr);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: POST /logout, POST /logout/all
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3logout
//
// "Invalidates an existing access token, so that it can no longer be used for authorisation.
// The device associated with the access token is also deleted." And for /logout/all: "All
// devices for the user are also deleted."
SCENARIO("Logging out deletes the device", "[conformance][client-server][auth][logout]")
{
    GIVEN("a user with two devices")
    {
        auto started = merovingian::homeserver::start_client_server(make_config(false));
        REQUIRE(started.started);
        auto const first_token = register_and_login(started.runtime, "alice", "DEVICE1");
        auto const second_token = login_again(started.runtime, "alice", "DEVICE2");
        REQUIRE(contains(device_ids(started.runtime, first_token), "DEVICE2"));

        WHEN("the second device logs out")
        {
            auto const logout = send(started.runtime, "POST", "/_matrix/client/v3/logout", second_token);
            REQUIRE(logout.status == 200U);

            THEN("the device is no longer listed, and the other device is")
            {
                auto const ids = device_ids(started.runtime, first_token);
                // Spec MUST: "The device associated with the access token is also deleted."
                REQUIRE_FALSE(contains(ids, "DEVICE2"));
                REQUIRE(contains(ids, "DEVICE1"));
            }
            THEN("the access token no longer authenticates")
            {
                // Spec MUST: the token "can no longer be used for authorisation".
                REQUIRE(send(started.runtime, "GET", "/_matrix/client/v3/devices", second_token).status == 401U);
            }
        }
        WHEN("the second device holds another access token, and one of them logs out")
        {
            auto const other_token_for_device = login_again(started.runtime, "alice", "DEVICE2");
            REQUIRE(send(started.runtime, "POST", "/_matrix/client/v3/logout", second_token).status == 200U);

            THEN("no token of the deleted device still authenticates")
            {
                // Spec MUST: deleting a device "invalidates any access token associated with it"
                // (DELETE /devices/{deviceId}); logout deletes the device.
                REQUIRE(send(started.runtime, "GET", "/_matrix/client/v3/devices", other_token_for_device).status ==
                        401U);
            }
        }
        WHEN("the second device has published its device keys and logs out")
        {
            auto const keys =
                R"({"device_keys":{"user_id":"@alice:example.org","device_id":"DEVICE2","algorithms":["m.olm.v1.curve25519-aes-sha2","m.megolm.v1.aes-sha2"],"keys":{"curve25519:DEVICE2":"curve-value","ed25519:DEVICE2":"ed-value"}}})";
            REQUIRE(send(started.runtime, "POST", "/_matrix/client/v3/keys/upload", second_token, keys).status == 200U);
            REQUIRE(send(started.runtime, "POST", "/_matrix/client/v3/logout", second_token).status == 200U);
            auto const query = send(started.runtime, "POST", "/_matrix/client/v3/keys/query", first_token,
                                    R"({"device_keys":{"@alice:example.org":[]}})");

            THEN("its keys are no longer published")
            {
                // Spec MUST: /keys/query returns "the current devices and identity keys" of the user; a
                // deleted device is not one, so others stop encrypting to it.
                REQUIRE(query.status == 200U);
                REQUIRE(query.body.find("DEVICE2") == std::string::npos);
            }
        }
        WHEN("the user logs out of every device")
        {
            REQUIRE(send(started.runtime, "POST", "/_matrix/client/v3/logout/all", first_token).status == 200U);
            auto const fresh_token = login_again(started.runtime, "alice", "DEVICE3");

            THEN("only the device logged in afterwards remains")
            {
                auto const ids = device_ids(started.runtime, fresh_token);
                // Spec MUST: "All devices for the user are also deleted."
                REQUIRE_FALSE(contains(ids, "DEVICE1"));
                REQUIRE_FALSE(contains(ids, "DEVICE2"));
                REQUIRE(contains(ids, "DEVICE3"));
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Using access tokens
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#using-access-tokens
//
// "When credentials are required but missing or invalid, the HTTP call will return with a status
// of 401 and the error code, `M_MISSING_TOKEN` or `M_UNKNOWN_TOKEN` respectively."
SCENARIO("A request that needs a token and carries none answers M_MISSING_TOKEN",
         "[conformance][client-server][auth][logout]")
{
    GIVEN("a running client-server")
    {
        auto started = merovingian::homeserver::start_client_server(make_config(false));
        REQUIRE(started.started);

        WHEN("POST /logout and POST /logout/all carry no access token")
        {
            auto const logout = send(started.runtime, "POST", "/_matrix/client/v3/logout");
            auto const logout_all = send(started.runtime, "POST", "/_matrix/client/v3/logout/all");
            THEN("each answers 401 M_MISSING_TOKEN")
            {
                // Spec MUST: a missing token is M_MISSING_TOKEN.
                REQUIRE(logout.status == 401U);
                REQUIRE(errcode_of(logout) == "M_MISSING_TOKEN");
                REQUIRE(logout_all.status == 401U);
                REQUIRE(errcode_of(logout_all) == "M_MISSING_TOKEN");
            }
        }
        WHEN("POST /logout carries a token the server never issued")
        {
            auto const logout = send(started.runtime, "POST", "/_matrix/client/v3/logout", "not-a-real-token");
            THEN("it answers 401 M_UNKNOWN_TOKEN")
            {
                // Spec MUST: an invalid token is M_UNKNOWN_TOKEN.
                REQUIRE(logout.status == 401U);
                REQUIRE(errcode_of(logout) == "M_UNKNOWN_TOKEN");
            }
        }
        WHEN("other token-protected endpoints carry no access token")
        {
            auto const devices = send(started.runtime, "GET", "/_matrix/client/v3/devices");
            auto const upload = send(started.runtime, "POST", "/_matrix/media/v3/upload", {}, "bytes");
            auto const create = send(started.runtime, "POST", "/_matrix/client/v3/createRoom", {}, "{}");
            THEN("each answers 401 M_MISSING_TOKEN")
            {
                // Spec MUST: a missing token is M_MISSING_TOKEN on every endpoint.
                REQUIRE(devices.status == 401U);
                REQUIRE(errcode_of(devices) == "M_MISSING_TOKEN");
                REQUIRE(upload.status == 401U);
                REQUIRE(errcode_of(upload) == "M_MISSING_TOKEN");
                REQUIRE(create.status == 401U);
                REQUIRE(errcode_of(create) == "M_MISSING_TOKEN");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: User-Interactive Authentication API; POST /register
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#user-interactive-authentication-api
//
// The session is "a session identifier that the client must pass back to the home server, if one
// is provided, in subsequent attempts to authenticate in the same API call" (ADR-0276). A
// single-shot request was provided none and completes; a session the server never issued is
// refused.
SCENARIO("Registration completes a single-shot dummy stage and refuses a session the server never issued",
         "[conformance][client-server][register][uia]")
{
    GIVEN("a server with acknowledged open registration")
    {
        auto started = merovingian::homeserver::start_client_server(make_config(true));
        REQUIRE(started.started);

        WHEN("m.login.dummy is submitted in one request, with no session")
        {
            auto const response =
                send(started.runtime, "POST", "/_matrix/client/v3/register", {},
                     R"({"username":"carol","password":"CorrectHorse7!","auth":{"type":"m.login.dummy"}})");
            THEN("the account is created")
            {
                // Spec: the client passes a session back only "if one is provided"; none was.
                REQUIRE(response.status == 200U);
            }
        }
        WHEN("m.login.dummy is submitted with a session this server never issued")
        {
            auto const response = send(
                started.runtime, "POST", "/_matrix/client/v3/register", {},
                R"({"username":"carol","password":"CorrectHorse7!","auth":{"type":"m.login.dummy","session":"never-issued"}})");
            THEN("registration does not complete and the 401 challenge is returned")
            {
                // Spec MUST: the session passed back is "the value of the session key given by the homeserver".
                REQUIRE(response.status == 401U);
                auto const body = parse_object(response.body);
                REQUIRE(object_member_as_array(body, "flows") != nullptr);
            }
        }
        WHEN("m.login.dummy is submitted with the session its challenge issued")
        {
            auto const challenge = send(started.runtime, "POST", "/_matrix/client/v3/register", {}, "{}");
            REQUIRE(challenge.status == 401U);
            auto const challenge_body = parse_object(challenge.body);
            auto const* session = string_member(challenge_body, "session");
            REQUIRE(session != nullptr);
            auto const response =
                send(started.runtime, "POST", "/_matrix/client/v3/register", {},
                     R"({"username":"carol","password":"CorrectHorse7!","auth":{"type":"m.login.dummy","session":")" +
                         *session + R"("}})");
            THEN("the account is created")
            {
                // Spec MUST: "Dummy authentication always succeeds" within its session.
                REQUIRE(response.status == 200U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: POST /register, 400 response
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3register
//
// "Homeservers MUST perform the relevant checks and return these codes before performing
// User-Interactive Authentication" (M_USER_IN_USE, M_INVALID_USERNAME, M_EXCLUSIVE).
SCENARIO("Registration refuses a taken or invalid username before User-Interactive Authentication",
         "[conformance][client-server][register][uia]")
{
    GIVEN("a server with token registration and an existing user alice")
    {
        auto started = merovingian::homeserver::start_client_server(make_config(false));
        REQUIRE(started.started);
        std::ignore = register_and_login(started.runtime, "alice", "DEVICE1");

        WHEN("a registration with no auth dict names the taken username")
        {
            auto const response = send(started.runtime, "POST", "/_matrix/client/v3/register", {},
                                       R"({"username":"alice","password":"CorrectHorse7!"})");
            THEN("it answers 400 M_USER_IN_USE rather than the UIA challenge")
            {
                // Spec MUST: the check is made "before performing User-Interactive Authentication".
                REQUIRE(response.status == 400U);
                REQUIRE(errcode_of(response) == "M_USER_IN_USE");
            }
        }
        WHEN("a registration with no auth dict names an invalid username")
        {
            auto const response = send(started.runtime, "POST", "/_matrix/client/v3/register", {},
                                       R"({"username":"not a valid name!","password":"CorrectHorse7!"})");
            THEN("it answers 400 M_INVALID_USERNAME")
            {
                // Spec MUST: the check is made "before performing User-Interactive Authentication".
                REQUIRE(response.status == 400U);
                REQUIRE(errcode_of(response) == "M_INVALID_USERNAME");
            }
        }
        WHEN("a registration with no auth dict names a username with an upper-case letter")
        {
            auto const response = send(started.runtime, "POST", "/_matrix/client/v3/register", {},
                                       R"({"username":"Carol","password":"CorrectHorse7!"})");
            THEN("it is still refused as an invalid username")
            {
                // Owner decision (ADR-0198 family): upper-case localparts are refused.
                REQUIRE(response.status == 400U);
                REQUIRE(errcode_of(response) == "M_INVALID_USERNAME");
            }
        }
        WHEN("a registration with no auth dict names a free, valid username")
        {
            auto const response = send(started.runtime, "POST", "/_matrix/client/v3/register", {},
                                       R"({"username":"carol","password":"CorrectHorse7!"})");
            THEN("it is challenged as before")
            {
                // Spec MUST: a UIA request "never succeeds without auth".
                REQUIRE(response.status == 401U);
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Standard error response, M_NOT_JSON
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#api-standards
//
// "`M_NOT_JSON`: Request did not contain valid JSON." and "`M_BAD_JSON`: Request contained valid
// JSON, but it was malformed in some way".
SCENARIO("A request body that is not valid JSON answers M_NOT_JSON", "[conformance][client-server][errors][json]")
{
    GIVEN("a registered user with a session")
    {
        auto started = merovingian::homeserver::start_client_server(make_config(false));
        REQUIRE(started.started);
        auto const token = register_and_login(started.runtime, "alice", "DEVICE1");

        auto const invalid_utf8 = std::string{"{\"username\":\"a\xff\xfe\"}"};

        WHEN("an unauthenticated endpoint receives invalid UTF-8 inside a JSON string")
        {
            auto const registration = send(started.runtime, "POST", "/_matrix/client/v3/register", {}, invalid_utf8);
            auto const login = send(started.runtime, "POST", "/_matrix/client/v3/login", {}, invalid_utf8);
            THEN("each answers 400 M_NOT_JSON")
            {
                // Spec MUST: a body that is not valid JSON is M_NOT_JSON.
                REQUIRE(registration.status == 400U);
                REQUIRE(errcode_of(registration) == "M_NOT_JSON");
                REQUIRE(login.status == 400U);
                REQUIRE(errcode_of(login) == "M_NOT_JSON");
            }
        }
        WHEN("authenticated endpoints receive a body that is not JSON")
        {
            auto const create = send(started.runtime, "POST", "/_matrix/client/v3/createRoom", token, invalid_utf8);
            auto const send_event =
                send(started.runtime, "PUT", "/_matrix/client/v3/rooms/!r:example.org/send/m.room.message/t1", token,
                     "{\"body\":");
            auto const account_data =
                send(started.runtime, "PUT", "/_matrix/client/v3/user/@alice:example.org/account_data/m.test", token,
                     "not json at all");
            THEN("each answers 400 M_NOT_JSON")
            {
                // Spec MUST: a body that is not valid JSON is M_NOT_JSON.
                REQUIRE(create.status == 400U);
                REQUIRE(errcode_of(create) == "M_NOT_JSON");
                REQUIRE(send_event.status == 400U);
                REQUIRE(errcode_of(send_event) == "M_NOT_JSON");
                REQUIRE(account_data.status == 400U);
                REQUIRE(errcode_of(account_data) == "M_NOT_JSON");
            }
        }
        WHEN("an endpoint receives valid JSON of the wrong shape")
        {
            auto const registration = send(started.runtime, "POST", "/_matrix/client/v3/register", {}, "[]");
            THEN("it answers M_BAD_JSON, not M_NOT_JSON")
            {
                // Spec: valid JSON that is malformed in some way is M_BAD_JSON.
                REQUIRE(registration.status == 400U);
                REQUIRE(errcode_of(registration) == "M_BAD_JSON");
            }
        }
    }
}

// Spec: Matrix Client-Server API v1.19
// Endpoint / Section: Standard error response, M_UNRECOGNIZED
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#api-standards
//
// "`M_UNRECOGNIZED`: The server did not understand the request. This is expected to be returned
// with a 404 HTTP status code if the endpoint is not implemented or a 405 HTTP status code if
// the endpoint is implemented, but the incorrect HTTP method is used."
SCENARIO("A known path used with an unsupported method answers 405 M_UNRECOGNIZED",
         "[conformance][client-server][errors][routing]")
{
    GIVEN("a registered user with a session")
    {
        auto started = merovingian::homeserver::start_client_server(make_config(false));
        REQUIRE(started.started);
        auto const token = register_and_login(started.runtime, "alice", "DEVICE1");

        WHEN("an unauthenticated client uses an unsupported method on a public client path")
        {
            auto const put_login = send(started.runtime, "PUT", "/_matrix/client/v3/login");
            auto const delete_login = send(started.runtime, "DELETE", "/_matrix/client/v3/login");
            auto const get_register = send(started.runtime, "GET", "/_matrix/client/v3/register");
            THEN("each answers 405 M_UNRECOGNIZED")
            {
                // Spec MUST: 405 "if the endpoint is implemented, but the incorrect HTTP method is used".
                REQUIRE(put_login.status == 405U);
                REQUIRE(errcode_of(put_login) == "M_UNRECOGNIZED");
                REQUIRE(delete_login.status == 405U);
                REQUIRE(errcode_of(delete_login) == "M_UNRECOGNIZED");
                REQUIRE(get_register.status == 405U);
                REQUIRE(errcode_of(get_register) == "M_UNRECOGNIZED");
            }
        }
        WHEN("a client uses an unsupported method on the media upload path")
        {
            auto const anonymous = send(started.runtime, "GET", "/_matrix/media/v3/upload");
            auto const authenticated = send(started.runtime, "DELETE", "/_matrix/media/v3/upload", token);
            THEN("each answers 405 M_UNRECOGNIZED")
            {
                // Spec MUST: 405 "if the endpoint is implemented, but the incorrect HTTP method is used".
                REQUIRE(anonymous.status == 405U);
                REQUIRE(errcode_of(anonymous) == "M_UNRECOGNIZED");
                REQUIRE(authenticated.status == 405U);
                REQUIRE(errcode_of(authenticated) == "M_UNRECOGNIZED");
            }
        }
        WHEN("an authenticated client uses an unsupported method on a path with identifiers in it")
        {
            auto const response =
                send(started.runtime, "POST", "/_matrix/client/v3/rooms/!r:example.org/joined_members", token, "{}");
            THEN("it answers 405 M_UNRECOGNIZED")
            {
                // Spec MUST: 405 "if the endpoint is implemented, but the incorrect HTTP method is used".
                REQUIRE(response.status == 405U);
                REQUIRE(errcode_of(response) == "M_UNRECOGNIZED");
            }
        }
        WHEN("a client asks for a path this server does not implement at all")
        {
            auto const anonymous = send(started.runtime, "GET", "/_matrix/client/v3/no/such/endpoint");
            auto const authenticated =
                send(started.runtime, "POST", "/_matrix/client/v3/no/such/endpoint", token, "{}");
            THEN("it still answers 404 M_UNRECOGNIZED")
            {
                // Spec MUST: 404 "if the endpoint is not implemented".
                REQUIRE(anonymous.status == 404U);
                REQUIRE(errcode_of(anonymous) == "M_UNRECOGNIZED");
                REQUIRE(authenticated.status == 404U);
                REQUIRE(errcode_of(authenticated) == "M_UNRECOGNIZED");
            }
        }
        WHEN("the supported methods are used on those same paths")
        {
            auto const flows = send(started.runtime, "GET", "/_matrix/client/v3/login");
            auto const devices = send(started.runtime, "GET", "/_matrix/client/v3/devices", token);
            THEN("they are served")
            {
                REQUIRE(flows.status == 200U);
                REQUIRE(devices.status == 200U);
            }
        }
    }
}

// Spec: Matrix Server-Server API v1.19
// Endpoint / Section: Standard error response, M_UNRECOGNIZED (Client-Server API § API standards)
// URL: ../../docs/matrix-v1.19-spec/client-server-api.md#api-standards
//
// The same rule holds for the federation surface: "a 405 HTTP status code if the endpoint is
// implemented, but the incorrect HTTP method is used".
SCENARIO("A known federation or key path used with an unsupported method answers 405 M_UNRECOGNIZED",
         "[conformance][federation][errors][routing]")
{
    GIVEN("a started homeserver")
    {
        auto started = merovingian::homeserver::start_runtime(make_config(false));
        REQUIRE(started.started);

        auto const federation = [&](std::string method, std::string target) {
            return merovingian::homeserver::handle_federation_http_request(
                started.runtime, {std::move(method), std::move(target), {}, {}});
        };

        WHEN("an unsupported method is used on the federation version path")
        {
            auto const response = federation("POST", "/_matrix/federation/v1/version");
            THEN("it answers 405 M_UNRECOGNIZED")
            {
                // Spec MUST: 405 "if the endpoint is implemented, but the incorrect HTTP method is used".
                REQUIRE(response.status == 405U);
                REQUIRE(errcode_of(response) == "M_UNRECOGNIZED");
            }
        }
        WHEN("an unsupported method is used on the server key path")
        {
            auto const response = federation("PUT", "/_matrix/key/v2/server");
            THEN("it answers 405 M_UNRECOGNIZED")
            {
                // Spec MUST: 405 "if the endpoint is implemented, but the incorrect HTTP method is used".
                REQUIRE(response.status == 405U);
                REQUIRE(errcode_of(response) == "M_UNRECOGNIZED");
            }
        }
        WHEN("an unsupported method is used on a transaction path")
        {
            auto const response = federation("GET", "/_matrix/federation/v1/send/txn1");
            THEN("it answers 405 M_UNRECOGNIZED before any signature is demanded")
            {
                // Spec MUST: 405 "if the endpoint is implemented, but the incorrect HTTP method is used".
                REQUIRE(response.status == 405U);
                REQUIRE(errcode_of(response) == "M_UNRECOGNIZED");
            }
        }
        WHEN("the supported method is used on the version path")
        {
            auto const response = federation("GET", "/_matrix/federation/v1/version");
            THEN("it is served")
            {
                REQUIRE(response.status == 200U);
            }
        }
    }
}
