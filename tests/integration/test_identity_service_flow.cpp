// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// +-------------------------------------------------------------------------+
// |         IS-DELEGATED 3PID BIND/UNBIND ROUND-TRIP INTEGRATION TEST       |
// |                                                                         |
// |  Spec: Matrix Client-Server API v1.19 — Adding Account Data via the IS |
// |  URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3account3pid |
// |  Spec: Matrix Identity Service API v2                                   |
// |  URL:  ../../docs/matrix-v1.19-spec/identity-service-api.md             |
// |                                                                         |
// |  Drives the full IS-delegated 3PID lifecycle (requestToken → bind →     |
// |  unbind) through a real local TLS mock identity server via the          |
// |  test_forced_identity_resolution seam. Proves that the unbind step      |
// |  drives IS auth mode 2: the HS recovers the stored (client_secret, sid) |
// |  pair from the bound record and sends them in the unbind body with NO   |
// |  bearer token (identity-service-api.md §3pid/unbind).                  |
// +-------------------------------------------------------------------------+

#include "../support/json_test_support.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/homeserver/runtime_mutex.hpp"
#include "merovingian/identity/identity_client.hpp"
#include "merovingian/net/tcp_acceptor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

namespace
{

using namespace merovingian::tests;

[[nodiscard]] auto integration_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
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

// Register and log in; returns the access token for subsequent requests.
[[nodiscard]] auto register_and_login(merovingian::homeserver::ClientServerRuntime& rt, std::string const& localpart)
    -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        rt, {"POST",
             "/_matrix/client/v3/register",
             {},
             merovingian::tests::registration_json(localpart, "CorrectHorse7!")});
    REQUIRE(reg.response.status == 200U);
    auto const login_body = std::string{R"({"type":"m.login.password","identifier":{"type":"m.id.user","user":"@)"} +
                            localpart + R"(:example.org"},"password":"CorrectHorse7!","device_id":")" + localpart +
                            R"(_DEV"})";
    auto const login =
        merovingian::homeserver::handle_client_server_request(rt, {"POST", "/_matrix/client/v3/login", {}, login_body});
    REQUIRE(login.response.status == 200U);
    auto const body = parse_object(login.response.body);
    auto const* tok = string_member(body, "access_token");
    REQUIRE(tok != nullptr);
    return *tok;
}

[[nodiscard]] auto find_captured(std::vector<std::string> const& captured, std::string_view needle)
    -> std::string const*
{
    for (auto const& req : captured)
    {
        if (req.find(needle) != std::string::npos)
        {
            return &req;
        }
    }
    return nullptr;
}

namespace tls_mock = merovingian::tests::tls_mock;
using merovingian::homeserver::ClientServerRuntime;
using tls_mock::MockIdentityServer;

constexpr auto password = std::string_view{"CorrectHorse7!"};
constexpr auto alice_user_id = std::string_view{"@alice:example.org"};
constexpr auto email_address = std::string_view{"alice@example.org"};
constexpr auto msisdn_address = std::string_view{"447700900123"};
constexpr auto validated_at_ms = std::uint64_t{1700000000000U};

[[nodiscard]] auto ok_response(std::string const& body) -> std::string
{
    return tls_mock::json_http_response("200 OK", body);
}

// What the IS answers to getValidated3pid when the owner has completed
// validation: the medium and address it validated, and when.
[[nodiscard]] auto validated_response(std::string_view address, std::string_view medium = "email") -> std::string
{
    return ok_response(std::string{R"({"address":")"} + std::string{address} + R"(","medium":")" + std::string{medium} +
                       R"(","validated_at":)" + std::to_string(validated_at_ms) + "}");
}

[[nodiscard]] auto not_validated_response() -> std::string
{
    return tls_mock::json_http_response(
        "400 Bad Request",
        R"({"errcode":"M_SESSION_NOT_VALIDATED","error":"This validation session has not yet been completed"})");
}

[[nodiscard]] auto identity_responses(std::string get_validated) -> MockIdentityServer::Responses
{
    return {
        {"validate/email/requestToken",  ok_response(R"({"sid":"is-sid-42"})")},
        {"validate/msisdn/requestToken", ok_response(R"({"sid":"is-sid-77"})")},
        {"getValidated3pid",             std::move(get_validated)             },
        {"3pid/bind",                    ok_response("{}")                    },
    };
}

[[nodiscard]] auto post(ClientServerRuntime& runtime, std::string const& target, std::string const& token,
                        std::string const& body)
{
    return merovingian::homeserver::handle_client_server_request(runtime, {"POST", target, token, body});
}

// requestToken body for an email or an msisdn; `identity_server` adds the
// id_server / id_access_token pair that delegates the validation to it.
[[nodiscard]] auto request_token_body(bool msisdn, std::string const& secret, MockIdentityServer const* identity_server)
    -> std::string
{
    auto body = std::string{R"({"client_secret":")"} + secret + R"(",)";
    body += msisdn ? R"("country":"GB","phone_number":")" + std::string{msisdn_address} + R"(",)"
                   : R"("email":")" + std::string{email_address} + R"(",)";
    body += R"("send_attempt":1)";
    if (identity_server != nullptr)
    {
        body += R"(,"id_server":")" + identity_server->host_port() + R"(","id_access_token":"opaque")";
    }
    return body + "}";
}

[[nodiscard]] auto uia_password_auth() -> std::string
{
    return std::string{R"("auth":{"type":"m.login.password","password":")"} + std::string{password} + R"("})";
}

enum class Route
{
    add,
    bind,
    legacy_bind
};

struct DriveParams final
{
    Route route{Route::add};
    // The raw HTTP response the identity server gives to getValidated3pid.
    std::string validation_response{};
    bool msisdn{false};
    // When set, the id_server the client names on /bind (default: the trusted mock).
    std::optional<std::string> bind_id_server{};
    // Points the session at an identity server that is not listening.
    bool identity_server_down{false};
};

struct Outcome final
{
    std::uint16_t status{0U};
    std::string body{};
    bool bound{false};
    std::uint64_t binding_validated_at_ms{0U};
    std::size_t sessions_remaining{0U};
    std::size_t validation_calls{0U};
    std::size_t identity_bind_calls{0U};
    std::string validation_request{};
};

// Runs one account 3PID association end to end: alice asks the trusted mock
// identity server for a token (it answers with a sid), then calls `route` with
// that sid. The mock answers getValidated3pid with `validation_response`.
[[nodiscard]] auto drive(DriveParams const& params) -> Outcome
{
    auto started = merovingian::homeserver::start_client_server(integration_config());
    REQUIRE(started.started);
    auto& runtime = started.runtime;
    auto const alice = register_and_login(runtime, "alice");

    auto identity_server = MockIdentityServer{identity_responses(params.validation_response)};
    identity_server.install(runtime);

    auto const secret = std::string{"test-secret-xyz"};
    auto const token_path = params.msisdn ? "/_matrix/client/v3/account/3pid/msisdn/requestToken"
                                          : "/_matrix/client/v3/account/3pid/email/requestToken";
    auto const requested =
        post(runtime, token_path, alice, request_token_body(params.msisdn, secret, &identity_server));
    REQUIRE(requested.response.status == 200U);
    auto const sid = std::string{params.msisdn ? "is-sid-77" : "is-sid-42"};

    if (params.identity_server_down)
    {
        REQUIRE(runtime.registration_validation_sessions.size() == 1U);
        runtime.registration_validation_sessions.front().identity_server_base_url = "https://is.localhost.test:1";
    }

    auto const id_server = params.bind_id_server.value_or(identity_server.host_port());
    auto response = std::pair<std::uint16_t, std::string>{};
    switch (params.route)
    {
    case Route::add: {
        auto const result =
            post(runtime, "/_matrix/client/v3/account/3pid/add", alice,
                 R"({"client_secret":")" + secret + R"(","sid":")" + sid + R"(",)" + uia_password_auth() + "}");
        response = {result.response.status, result.response.body};
        break;
    }
    case Route::bind: {
        auto const result = post(runtime, "/_matrix/client/v3/account/3pid/bind", alice,
                                 R"({"client_secret":")" + secret + R"(","sid":")" + sid + R"(","id_server":")" +
                                     id_server + R"(","id_access_token":"opaque"})");
        response = {result.response.status, result.response.body};
        break;
    }
    case Route::legacy_bind: {
        auto const result = post(runtime, "/_matrix/client/v3/account/3pid", alice,
                                 R"({"three_pid_creds":{"client_secret":")" + secret + R"(","sid":")" + sid +
                                     R"(","id_server":")" + id_server + R"(","id_access_token":"opaque"}})");
        response = {result.response.status, result.response.body};
        break;
    }
    }

    auto outcome = Outcome{};
    outcome.status = response.first;
    outcome.body = response.second;
    auto const binding = merovingian::database::find_account_threepid(runtime.homeserver.database.persistent_store,
                                                                      alice_user_id, params.msisdn ? "msisdn" : "email",
                                                                      params.msisdn ? msisdn_address : email_address);
    outcome.bound = binding.has_value();
    outcome.binding_validated_at_ms = binding.has_value() ? binding->validated_at_ms : 0U;
    outcome.sessions_remaining = runtime.registration_validation_sessions.size();
    outcome.validation_calls = identity_server.count_requests("getValidated3pid");
    outcome.identity_bind_calls = identity_server.count_requests("3pid/bind");
    for (auto const& request : identity_server.requests())
    {
        if (request.find("getValidated3pid") != std::string::npos)
        {
            outcome.validation_request = request;
        }
    }
    return outcome;
}

} // namespace

// Spec: Matrix Client-Server API v1.19 — Adding Account Data via the IS;
// Identity Service API v2
// URL:  ../../docs/matrix-v1.19-spec/client-server-api.md#post_matrixclientv3account3pid
// URL:  ../../docs/matrix-v1.19-spec/identity-service-api.md
//
// Spec MUST (identity-service-api.md §3pid/unbind): the HS unbinds a 3PID at
// the IS using the stored validation credentials (client_secret + sid) —
// "mode 2" — without a homeserver-signed/bearer-authenticated request. This
// test proves the HS persists the (client_secret, sid) pair at bind time and
// recovers them for the unbind body, and that the unbind request carries no
// Authorization: Bearer header.
SCENARIO("IS-delegated 3PID bind/unbind round-trip unbinds via stored client_secret+sid (mode 2)",
         "[homeserver][identity][integration]")
{
    GIVEN("alice registered and a trusted mock identity server")
    {
        auto started = merovingian::homeserver::start_client_server(integration_config());
        REQUIRE(started.started);

        auto const alice = register_and_login(started.runtime, "alice");

        auto const is_host = std::string{"is.localhost.test"};

        // Stand up the mock IS on a real local TLS socket. The certificate CN
        // must be the IS host: the HS verifies the peer name against the URL
        // host, so a "localhost" CN would fail the handshake here.
        auto cert = merovingian::tests::tls_mock::write_test_tls_certificate(is_host);
        auto tls_ctx = merovingian::homeserver::make_tls_server_context(cert.certificate_file, cert.private_key_file);
        REQUIRE(tls_ctx.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto const is_host_port = is_host + ":" + std::to_string(port);
        auto const is_base_url = std::string{"https://"} + is_host_port;

        // Configure trust BEFORE dispatching. resolve_trusted_identity_base_url
        // (client_server.cpp) parses each trusted_servers entry as an https URL
        // and matches host+port against the client's id_server (host:port).
        started.runtime.homeserver.config.server().identity_server.default_server = is_base_url;
        started.runtime.homeserver.config.server().identity_server.trusted_servers = {is_base_url};

        // Test-only seam: pin the IS host to loopback, trust the self-signed cert.
        started.runtime.homeserver.test_forced_identity_resolution[is_host] =
            merovingian::identity::TestForcedIdentityResolution{{"127.0.0.1"}, cert.certificate_pem};

        // Canned IS responses for the three sequential requests.
        auto const request_token_response =
            merovingian::tests::tls_mock::json_http_response("200 OK", R"({"sid":"is-sid-42"})");
        auto const bind_response = merovingian::tests::tls_mock::json_http_response("200 OK", "{}");
        auto const unbind_response = merovingian::tests::tls_mock::json_http_response("200 OK", "{}");

        auto captured_requests = std::vector<std::string>{};
        auto server_thread = std::thread{[&] {
            merovingian::tests::tls_mock::run_path_dispatch_tls_server(
                acceptor, *tls_ctx.context,
                {
                    {"validate/email/requestToken", request_token_response                 },
                    {"getValidated3pid",            validated_response("alice@example.org")},
                    {"3pid/bind",                   bind_response                          },
                    {"3pid/unbind",                 unbind_response                        }
            },
                &captured_requests);
        }};
        auto const server_join = merovingian::tests::tls_mock::ScopedThreadJoin{server_thread};

        WHEN("alice runs requestToken → bind → unbind against the mock IS")
        {
            // 1. requestToken: the IS issues a sid and the HS records a local
            // validation session keyed by (sid, client_secret).
            auto const request_token_body =
                std::string{R"({"client_secret":"test-secret-xyz","email":"alice@example.org","send_attempt":1,)"
                            R"("id_server":")"} +
                is_host_port + R"(","id_access_token":"opaque"})";
            auto const request_token = merovingian::homeserver::handle_client_server_request(
                started.runtime,
                {"POST", "/_matrix/client/v3/account/3pid/email/requestToken", alice, request_token_body});
            REQUIRE(request_token.response.status == 200U);
            auto const rt_body = parse_object(request_token.response.body);
            auto const* sid = string_member(rt_body, "sid");
            REQUIRE(sid != nullptr);
            REQUIRE(*sid == "is-sid-42");

            // 2. bind: the HS calls IS /3pid/bind and persists the 3PID with the
            // (client_secret, sid) pair so a later unbind can drive mode 2.
            auto const bind_body = std::string{R"({"client_secret":"test-secret-xyz","sid":"is-sid-42",)"
                                               R"("id_server":")"} +
                                   is_host_port + R"(","id_access_token":"opaque"})";
            auto const bind = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/account/3pid/bind", alice, bind_body});
            REQUIRE(bind.response.status == 200U);

            // 3. delete (unbind): the HS finds the stored (client_secret, sid),
            // calls IS /3pid/unbind with mode 2 (no bearer), then removes the
            // local binding.
            auto const delete_body = std::string{R"({"address":"alice@example.org","medium":"email","id_server":")"} +
                                     is_host_port + R"("})";
            auto const del = merovingian::homeserver::handle_client_server_request(
                started.runtime, {"POST", "/_matrix/client/v3/account/3pid/delete", alice, delete_body});
            REQUIRE(del.response.status == 200U);
            auto const del_body = parse_object(del.response.body);
            auto const* unbind_result = string_member(del_body, "id_server_unbind_result");
            REQUIRE(unbind_result != nullptr);
            REQUIRE(*unbind_result == "success");

            server_thread.join();

            THEN("the unbind request body carries the stored client_secret and sid and no bearer")
            {
                // The unbind request is the one whose path contains "3pid/unbind".
                auto const* unbind_request = find_captured(captured_requests, "3pid/unbind");
                REQUIRE(unbind_request != nullptr);

                // Spec MUST (mode 2): the HS recovered the stored pair and sent
                // them in the unbind body.
                REQUIRE(unbind_request->find("\"client_secret\":\"test-secret-xyz\"") != std::string::npos);
                REQUIRE(unbind_request->find("\"sid\":\"is-sid-42\"") != std::string::npos);

                // Spec MUST (mode 2): the unbind is unauthenticated — no bearer
                // token. (requestToken and bind carry the bearer; unbind must not.)
                REQUIRE(unbind_request->find("Authorization: Bearer") == std::string::npos);

                // AND the persisted binding was cleared by delete: the (user,
                // medium, address) tuple is no longer present in the store.
                auto const& store = started.runtime.homeserver.database.persistent_store;
                auto const remaining =
                    merovingian::database::find_account_threepid(store, alice_user_id, "email", "alice@example.org");
                REQUIRE_FALSE(remaining.has_value());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// AUTH-5: 3PID ownership is proven only through a trusted identity server.
//
// Spec (client-server-api.md, 3pid/email/requestToken, 400): "M_SERVER_NOT_TRUSTED"
// when the id_server is not trusted; (3pid/add, 400): "M_THREEPID_MEDIUM_NOT_SUPPORTED:
// The homeserver does not support adding email addresses." This server cannot send
// email or SMS, so without a trusted identity server it supports neither medium.
// Spec (identity-service-api.md, getValidated3pid): the IS answers 200 with
// {address, medium, validated_at} once validated, 400 M_SESSION_NOT_VALIDATED when
// not, 404 for an unknown session.
// ---------------------------------------------------------------------------

SCENARIO("requestToken without a trusted identity server is refused and creates no session",
         "[homeserver][identity][integration][auth][3pid][auth-5]")
{
    GIVEN("a running server that can send no email or SMS of its own")
    {
        auto started = merovingian::homeserver::start_client_server(integration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        auto const endpoints = std::vector<std::pair<std::string, bool>>{
            {"/_matrix/client/v3/register/email/requestToken",      false},
            {"/_matrix/client/v3/register/msisdn/requestToken",     true },
            {"/_matrix/client/v3/account/3pid/email/requestToken",  false},
            {"/_matrix/client/v3/account/3pid/msisdn/requestToken", true },
        };

        WHEN("each requestToken endpoint is called with no id_server")
        {
            auto statuses = std::vector<std::uint16_t>{};
            auto errcodes = std::vector<std::string>{};
            for (auto const& [target, msisdn] : endpoints)
            {
                auto const response = post(runtime, target, {}, request_token_body(msisdn, "secret123", nullptr));
                statuses.push_back(response.response.status);
                auto const error_body = parse_object(response.response.body);
                auto const* errcode = string_member(error_body, "errcode");
                errcodes.push_back(errcode != nullptr ? *errcode : std::string{});
            }

            THEN("every one is refused with M_THREEPID_MEDIUM_NOT_SUPPORTED and no session exists")
            {
                REQUIRE(statuses == std::vector<std::uint16_t>(4U, 400U));
                REQUIRE(errcodes == std::vector<std::string>(4U, "M_THREEPID_MEDIUM_NOT_SUPPORTED"));
                REQUIRE(runtime.registration_validation_sessions.empty());
            }
        }

        WHEN("each requestToken endpoint names an identity server this server does not trust")
        {
            auto statuses = std::vector<std::uint16_t>{};
            for (auto const& [target, msisdn] : endpoints)
            {
                auto body = request_token_body(msisdn, "secret123", nullptr);
                body.pop_back();
                body += R"(,"id_server":"untrusted.example.net","id_access_token":"opaque"})";
                statuses.push_back(post(runtime, target, {}, body).response.status);
            }

            THEN("the existing untrusted-server refusal is kept and no session exists")
            {
                REQUIRE(statuses == std::vector<std::uint16_t>(4U, 403U));
                REQUIRE(runtime.registration_validation_sessions.empty());
            }
        }

        WHEN("an id_server is named without an id_access_token")
        {
            auto body = request_token_body(false, "secret123", nullptr);
            body.pop_back();
            body += R"(,"id_server":"untrusted.example.net"})";
            auto const response = post(runtime, "/_matrix/client/v3/account/3pid/email/requestToken", {}, body);

            THEN("it is a bad request and no session exists")
            {
                REQUIRE(response.response.status == 400U);
                REQUIRE(runtime.registration_validation_sessions.empty());
            }
        }
    }
}

SCENARIO("A delegated validation session starts unvalidated and remembers its identity server in memory only",
         "[homeserver][identity][integration][auth][3pid][auth-5]")
{
    GIVEN("a trusted identity server that issues a sid for every requestToken")
    {
        auto started = merovingian::homeserver::start_client_server(integration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto identity_server = MockIdentityServer{identity_responses(not_validated_response())};
        identity_server.install(runtime);

        WHEN("all four requestToken endpoints are called through it")
        {
            auto statuses = std::vector<std::uint16_t>{};
            statuses.push_back(post(runtime, "/_matrix/client/v3/register/email/requestToken", {},
                                    request_token_body(false, "secret-1", &identity_server))
                                   .response.status);
            statuses.push_back(post(runtime, "/_matrix/client/v3/register/msisdn/requestToken", {},
                                    request_token_body(true, "secret-2", &identity_server))
                                   .response.status);
            statuses.push_back(post(runtime, "/_matrix/client/v3/account/3pid/email/requestToken", {},
                                    request_token_body(false, "secret-3", &identity_server))
                                   .response.status);
            statuses.push_back(post(runtime, "/_matrix/client/v3/account/3pid/msisdn/requestToken", {},
                                    request_token_body(true, "secret-4", &identity_server))
                                   .response.status);

            THEN("each session is unvalidated and carries the IS URL and the caller's IS token")
            {
                REQUIRE(statuses == std::vector<std::uint16_t>(4U, 200U));
                REQUIRE(runtime.registration_validation_sessions.size() == 4U);
                for (auto const& session : runtime.registration_validation_sessions)
                {
                    REQUIRE(session.validated_at_ms == 0U);
                    REQUIRE(session.identity_server_base_url == identity_server.base_url());
                    REQUIRE(session.identity_access_token == "opaque");
                }
                REQUIRE(identity_server.count_requests("getValidated3pid") == 0U);
            }
        }
    }
}

SCENARIO("POST /account/3pid/add binds a 3PID only after the identity server reports the session validated",
         "[homeserver][identity][integration][auth][3pid][auth-5]")
{
    GIVEN("a delegated session whose identity server says it is NOT validated")
    {
        auto const outcome = [] {
            auto params = DriveParams{};
            params.route = Route::add;
            params.validation_response = not_validated_response();
            return drive(params);
        }();

        THEN("add is refused with M_SESSION_NOT_VALIDATED and nothing is bound")
        {
            REQUIRE(outcome.status == 400U);
            REQUIRE(outcome.body.find("M_SESSION_NOT_VALIDATED") != std::string::npos);
            REQUIRE_FALSE(outcome.bound);
            REQUIRE(outcome.validation_calls == 1U);
            // The caller may validate (click the link) and retry, so the session survives.
            REQUIRE(outcome.sessions_remaining == 1U);
        }

        THEN("the identity server was asked with the sid, the client secret and the IS bearer token")
        {
            REQUIRE(outcome.validation_request.starts_with("GET /_matrix/identity/v2/3pid/getValidated3pid?"));
            REQUIRE(outcome.validation_request.find("sid=is-sid-42") != std::string::npos);
            REQUIRE(outcome.validation_request.find("client_secret=test-secret-xyz") != std::string::npos);
            REQUIRE(outcome.validation_request.find("Authorization: Bearer opaque") != std::string::npos);
        }
    }

    GIVEN("a delegated session the identity server reports validated for the same address")
    {
        auto const outcome = [] {
            auto params = DriveParams{};
            params.route = Route::add;
            params.validation_response = validated_response(email_address);
            return drive(params);
        }();

        THEN("the 3PID is bound with the identity server's validation time and the session is consumed")
        {
            REQUIRE(outcome.status == 200U);
            REQUIRE(outcome.bound);
            REQUIRE(outcome.binding_validated_at_ms == validated_at_ms);
            REQUIRE(outcome.sessions_remaining == 0U);
        }
    }

    GIVEN("a delegated session the identity server reports validated for a DIFFERENT address")
    {
        auto const outcome = [] {
            auto params = DriveParams{};
            params.route = Route::add;
            params.validation_response = validated_response("mallory@example.org");
            return drive(params);
        }();

        THEN("add is refused and nothing is bound")
        {
            REQUIRE(outcome.status == 400U);
            REQUIRE(outcome.body.find("M_SESSION_NOT_VALIDATED") != std::string::npos);
            REQUIRE_FALSE(outcome.bound);
        }
    }

    GIVEN("a delegated session the identity server reports validated for the right address but another medium")
    {
        auto const outcome = [] {
            auto params = DriveParams{};
            params.route = Route::add;
            params.validation_response = validated_response(email_address, "msisdn");
            return drive(params);
        }();

        THEN("add is refused and nothing is bound")
        {
            REQUIRE(outcome.status == 400U);
            REQUIRE_FALSE(outcome.bound);
        }
    }

    GIVEN("a delegated msisdn session")
    {
        auto const matching = [] {
            auto params = DriveParams{};
            params.route = Route::add;
            params.msisdn = true;
            params.validation_response = validated_response(msisdn_address, "msisdn");
            return drive(params);
        }();
        auto const other_number = [] {
            auto params = DriveParams{};
            params.route = Route::add;
            params.msisdn = true;
            params.validation_response = validated_response("447700900999", "msisdn");
            return drive(params);
        }();

        THEN("it is bound only when the identity server validated that number")
        {
            REQUIRE(matching.status == 200U);
            REQUIRE(matching.bound);
            REQUIRE(other_number.status == 400U);
            REQUIRE_FALSE(other_number.bound);
        }
    }

    GIVEN("an identity server that errors, answers with garbage, does not know the session or is down")
    {
        auto const server_error = [] {
            auto params = DriveParams{};
            params.validation_response =
                tls_mock::json_http_response("500 Internal Server Error", R"({"errcode":"M_UNKNOWN"})");
            return drive(params);
        }();
        auto const malformed = [] {
            auto params = DriveParams{};
            params.validation_response = ok_response(R"({"address":"alice@example.org"})");
            return drive(params);
        }();
        auto const unknown_session = [] {
            auto params = DriveParams{};
            params.validation_response =
                tls_mock::json_http_response("404 Not Found", R"({"errcode":"M_NO_VALID_SESSION"})");
            return drive(params);
        }();
        auto const down = [] {
            auto params = DriveParams{};
            params.validation_response = validated_response(email_address);
            params.identity_server_down = true;
            return drive(params);
        }();

        THEN("add fails closed in every case and nothing is bound")
        {
            REQUIRE(server_error.status != 200U);
            REQUIRE_FALSE(server_error.bound);
            REQUIRE(malformed.status != 200U);
            REQUIRE_FALSE(malformed.bound);
            REQUIRE(unknown_session.status == 400U);
            REQUIRE_FALSE(unknown_session.bound);
            REQUIRE(down.status == 502U);
            REQUIRE(down.body.find("M_UNREACHABLE") != std::string::npos);
            REQUIRE_FALSE(down.bound);
        }
    }
}

SCENARIO("POST /account/3pid/bind and the legacy POST /account/3pid bind only a session the identity server validated",
         "[homeserver][identity][integration][auth][3pid][auth-5]")
{
    GIVEN("each bind route and an identity server that says the session is NOT validated")
    {
        auto const bind = [] {
            auto params = DriveParams{};
            params.route = Route::bind;
            params.validation_response = not_validated_response();
            return drive(params);
        }();
        auto const legacy = [] {
            auto params = DriveParams{};
            params.route = Route::legacy_bind;
            params.validation_response = not_validated_response();
            return drive(params);
        }();

        THEN("both are refused with M_SESSION_NOT_VALIDATED, the identity server is never asked to bind, and "
             "nothing is bound locally")
        {
            for (auto const* outcome : {&bind, &legacy})
            {
                REQUIRE(outcome->status == 400U);
                REQUIRE(outcome->body.find("M_SESSION_NOT_VALIDATED") != std::string::npos);
                REQUIRE_FALSE(outcome->bound);
                REQUIRE(outcome->identity_bind_calls == 0U);
            }
        }
    }

    GIVEN("each bind route and an identity server that says the session is validated for the same address")
    {
        auto const bind = [] {
            auto params = DriveParams{};
            params.route = Route::bind;
            params.validation_response = validated_response(email_address);
            return drive(params);
        }();
        auto const legacy = [] {
            auto params = DriveParams{};
            params.route = Route::legacy_bind;
            params.validation_response = validated_response(email_address);
            return drive(params);
        }();

        THEN("both bind at the identity server once, record the binding, and consume the session")
        {
            for (auto const* outcome : {&bind, &legacy})
            {
                REQUIRE(outcome->status == 200U);
                REQUIRE(outcome->bound);
                REQUIRE(outcome->identity_bind_calls == 1U);
                REQUIRE(outcome->binding_validated_at_ms == validated_at_ms);
                REQUIRE(outcome->sessions_remaining == 0U);
            }
        }
    }

    GIVEN("each bind route and an identity server that validated a DIFFERENT address")
    {
        auto const bind = [] {
            auto params = DriveParams{};
            params.route = Route::bind;
            params.validation_response = validated_response("mallory@example.org");
            return drive(params);
        }();
        auto const legacy = [] {
            auto params = DriveParams{};
            params.route = Route::legacy_bind;
            params.validation_response = validated_response("mallory@example.org");
            return drive(params);
        }();

        THEN("both are refused and the identity server is never asked to bind")
        {
            for (auto const* outcome : {&bind, &legacy})
            {
                REQUIRE(outcome->status == 400U);
                REQUIRE_FALSE(outcome->bound);
                REQUIRE(outcome->identity_bind_calls == 0U);
            }
        }
    }

    GIVEN("a validated session but a bind to an identity server this server does not trust")
    {
        auto const bind = [] {
            auto params = DriveParams{};
            params.route = Route::bind;
            params.validation_response = validated_response(email_address);
            params.bind_id_server = "untrusted.example.net";
            return drive(params);
        }();

        THEN("it is refused with M_SERVER_NOT_TRUSTED rather than recording a bind that never happened")
        {
            REQUIRE(bind.status == 400U);
            REQUIRE(bind.body.find("M_SERVER_NOT_TRUSTED") != std::string::npos);
            REQUIRE_FALSE(bind.bound);
            REQUIRE(bind.identity_bind_calls == 0U);
        }
    }
}

SCENARIO("A validation check against the identity server holds no runtime lock and re-checks the session afterwards",
         "[homeserver][identity][integration][auth][3pid][auth-5][locking]")
{
    GIVEN("a delegated session and an identity server that stalls getValidated3pid")
    {
        auto started = merovingian::homeserver::start_client_server(integration_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = register_and_login(runtime, "alice");
        auto identity_server = MockIdentityServer{identity_responses(validated_response(email_address))};
        identity_server.install(runtime);
        identity_server.stall_requests_matching("getValidated3pid");

        auto const requested = post(runtime, "/_matrix/client/v3/account/3pid/email/requestToken", alice,
                                    request_token_body(false, "test-secret-xyz", &identity_server));
        REQUIRE(requested.response.status == 200U);

        WHEN("add is in flight and the session expires before the identity server answers")
        {
            // Catch2 assertions are not thread-safe: the worker only records
            // what it saw and every REQUIRE runs on the main thread.
            auto add_status = std::atomic<std::uint16_t>{0U};
            auto add_thread = std::thread{[&] {
                auto const response =
                    post(runtime, "/_matrix/client/v3/account/3pid/add", alice,
                         R"({"client_secret":"test-secret-xyz","sid":"is-sid-42",)" + uia_password_auth() + "}");
                add_status.store(response.response.status);
            }};
            auto const add_join = tls_mock::ScopedThreadJoin{add_thread};
            auto const peer_saw_request =
                tls_mock::wait_for_flag(identity_server.stall_seen(), std::chrono::seconds{10});

            auto const start = std::chrono::steady_clock::now();
            auto const capabilities = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/capabilities", alice, {}});
            auto const elapsed = std::chrono::steady_clock::now() - start;
            {
                // The runtime mutex is free: this takes it while the IS call is still pending.
                auto const lock = std::lock_guard<merovingian::homeserver::RuntimeMutex>{runtime.homeserver.mutex};
                runtime.registration_validation_sessions.clear();
            }
            identity_server.release_stall();
            add_thread.join();

            THEN("an unrelated request completed meanwhile, and add refused the vanished session")
            {
                REQUIRE(peer_saw_request);
                REQUIRE(capabilities.response.status == 200U);
                REQUIRE(elapsed < std::chrono::seconds{2});
                REQUIRE(add_status.load() == 400U);
                REQUIRE_FALSE(merovingian::database::find_account_threepid(runtime.homeserver.database.persistent_store,
                                                                           alice_user_id, "email", email_address)
                                  .has_value());
            }
        }
    }
}
