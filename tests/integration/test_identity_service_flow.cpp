// SPDX-License-Identifier: GPL-3.0-or-later
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
#include "../support/registration_token.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/database/persistent_store.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/local_http_router.hpp"
#include "merovingian/identity/identity_client.hpp"
#include "merovingian/net/tcp_acceptor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
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
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

// Register and log in; returns the access token for subsequent requests.
[[nodiscard]] auto register_and_login(merovingian::homeserver::ClientServerRuntime& rt,
                                      std::string const& localpart) -> std::string
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

[[nodiscard]] auto find_captured(std::vector<std::string> const& captured,
                                 std::string_view needle) -> std::string const*
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
        auto const alice_user_id = std::string{"@alice:example.org"};

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
                    {"validate/email/requestToken", request_token_response},
                    {"3pid/bind",                   bind_response         },
                    {"3pid/unbind",                 unbind_response       }
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
