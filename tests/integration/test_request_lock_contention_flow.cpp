// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Regression cover for the global-stall bug: HomeserverRuntime::mutex was held
// across blocking outbound federation calls, so one slow or unreachable peer
// froze every other client-server request and every inbound federation
// transaction for the full duration of the remote timeout.
//
// These tests stand up a real TLS peer that accepts the connection and then
// refuses to answer, and assert that the rest of the server keeps serving while
// that call is still in flight.

#include "../support/json_test_support.hpp"
#include "../support/registration_token.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/runtime.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/net/tcp_acceptor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <atomic>
#include <chrono>
#include <string>
#include <string_view>
#include <thread>

#include <sodium.h>

using namespace merovingian::tests;
using namespace std::chrono_literals;

namespace
{

// The peer that never answers promptly. Any name works — the destination is
// pinned through test_forced_outbound_resolution, never resolved for real.
constexpr auto stalled_server = std::string_view{"stalled.example.org"};

// Generous enough that a still-broken build cannot pass by luck, bounded so a
// broken build fails on the assertion instead of timing out the suite.
constexpr auto max_stall = 8000ms;
// A request that only touches local state must not come anywhere near the
// stall. The gap between the two is the whole assertion.
constexpr auto responsive_budget = 3000ms;

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
}

[[nodiscard]] auto register_and_login(merovingian::homeserver::ClientServerRuntime& runtime) -> std::string
{
    auto const registration = merovingian::homeserver::handle_client_server_request(
        runtime,
        {"POST", "/_matrix/client/v3/register", {}, merovingian::tests::registration_json("alice", "CorrectHorse7!")});
    REQUIRE(registration.response.status == 200U);
    auto const body = parse_object(registration.response.body);
    auto const* token = string_member(body, "access_token");
    REQUIRE(token != nullptr);
    REQUIRE(!token->empty());
    return *token;
}

} // namespace

SCENARIO("A stalled outbound federation call leaves the rest of the server responsive",
         "[homeserver][client-server][integration][concurrency][locking]")
{
    GIVEN("a running homeserver and a remote peer that accepts a request but withholds its response")
    {
        REQUIRE(sodium_init() >= 0);

        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const access_token = register_and_login(runtime);

        auto const certificate = tls_mock::write_test_tls_certificate();
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        // Pin the destination at our local TLS server, trusting its self-signed
        // certificate, without touching discovery or the system trust store.
        runtime.homeserver.test_forced_outbound_resolution[std::string{stalled_server}] =
            merovingian::homeserver::TestOnlyForcedOutboundResolution{
                "localhost", port, {"127.0.0.1"}, certificate.certificate_pem};

        auto stall = tls_mock::StallingTlsServerState{};
        auto const late_response = tls_mock::json_http_response("200 OK", R"({"device_keys":{}})");
        auto server_thread = std::thread{[&]() {
            tls_mock::run_stalling_tls_server(acceptor, *tls_context.context, stall, late_response, max_stall);
        }};
        auto const server_join = tls_mock::ScopedThreadJoin{server_thread};

        WHEN("a key query for a user on that peer is in flight")
        {
            // Catch2 assertion macros are not thread-safe, so the worker thread
            // only records what it saw; every REQUIRE runs on the main thread.
            auto query_status = std::atomic<std::uint16_t>{0U};
            auto query_thread = std::thread{[&]() {
                auto const response = merovingian::homeserver::handle_client_server_request(
                    runtime, {"POST", "/_matrix/client/v3/keys/query", access_token,
                              std::string{R"({"device_keys":{"@bob:)"} + std::string{stalled_server} + R"(":[]}})"});
                query_status.store(response.response.status);
            }};
            auto const query_join = tls_mock::ScopedThreadJoin{query_thread};

            auto const peer_saw_request = tls_mock::wait_for_flag(stall.request_received, max_stall);

            THEN("an unrelated client request still completes promptly")
            {
                auto const start = std::chrono::steady_clock::now();
                auto const capabilities = merovingian::homeserver::handle_client_server_request(
                    runtime, {"GET", "/_matrix/client/v3/capabilities", access_token, {}});
                auto const elapsed = std::chrono::steady_clock::now() - start;

                // Release the peer and reap the query before asserting, so a
                // failure reports as a failure rather than stalling the thread
                // joins behind it. ScopedThreadJoin remains as the safety net
                // for the paths that do not reach this point.
                stall.released.store(true);
                query_thread.join();

                REQUIRE(peer_saw_request);
                REQUIRE(capabilities.response.status == 200U);
                REQUIRE(elapsed < responsive_budget);
                // The stalled query still succeeds once the peer answers —
                // releasing the lock must not have broken the call itself.
                REQUIRE(query_status.load() == 200U);
            }
        }
    }
}
