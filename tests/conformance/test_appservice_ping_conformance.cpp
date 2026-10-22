// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |      APPLICATION SERVICE API — PINGING (v1.7), WAVE 3 OF THE AUDIT       |
// |                                                                         |
// |  Spec: Matrix Application Service API v1.19, "Pinging"                 |
// |  URL:  ../../docs/matrix-v1.19-spec/application-service-api.md#pinging  |
// |                                                                         |
// |  POST /_matrix/client/v1/appservice/{appserviceId}/ping asks the        |
// |  homeserver to call POST /_matrix/app/v1/ping on the appservice. These  |
// |  drive a real loopback mock appservice and assert on what it received.  |
// +-------------------------------------------------------------------------+

#include "../support/appservice_test_config.hpp"
#include "../support/joining_threads.hpp"
#include "../support/json_test_support.hpp"
#include "../support/mock_appservice.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/net/tcp_acceptor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace
{

using namespace std::chrono_literals;
using merovingian::homeserver::ClientServerRuntime;
using merovingian::tests::MockAppservice;
using merovingian::tests::TestAppservice;

[[nodiscard]] auto ping(ClientServerRuntime& runtime, std::string const& appservice_id, std::string const& token,
                        std::string body = {})
{
    return merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v1/appservice/" + appservice_id + "/ping", token, std::move(body)});
}

[[nodiscard]] auto errcode_of(merovingian::homeserver::DispatchResult const& result) -> std::string
{
    auto const body = merovingian::tests::parse_object(result.response.body);
    auto const* errcode = merovingian::tests::string_member(body, "errcode");
    return errcode == nullptr ? std::string{} : *errcode;
}

// A port nothing listens on: bound to learn a free number, then released.
[[nodiscard]] auto closed_port() -> std::uint16_t
{
    auto acceptor = merovingian::net::TcpAcceptor{};
    REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
    return acceptor.bound_port();
}

} // namespace

// Spec: Application Service API v1.19
// Endpoint / Section: POST /_matrix/client/v1/appservice/{appserviceId}/ping
// URL: ../../docs/matrix-v1.19-spec/application-service-api.md#post_matrixclientv1appserviceappserviceidping
//
// "This API asks the homeserver to call the /_matrix/app/v1/ping endpoint on the application service to
// ensure that the homeserver can communicate with the application service." 200: "The ping was
// successful." with `duration_ms`, "The duration in milliseconds that the /_matrix/app/v1/ping request took
// from the homeserver's point of view." The outbound call carries the `transaction_id` and the hs_token.
SCENARIO("a ping that the appservice answers is a 200 with duration_ms", "[appservice][conformance][ping]")
{
    GIVEN("an appservice that answers 200 to everything")
    {
        auto bridge = TestAppservice{.id = "bridge"};
        auto mock = MockAppservice{};
        bridge.url = mock.url();
        auto started =
            merovingian::homeserver::start_client_server(merovingian::tests::appservice_test_config({bridge}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("it pings itself with a transaction_id")
        {
            auto const result = ping(runtime, "bridge", bridge.as_token(), R"({"transaction_id":"mautrix-go_1_123"})");

            THEN("the answer is 200 with an integer duration_ms")
            {
                // Spec MUST: "200: The ping was successful."
                REQUIRE(result.response.status == 200U);
                auto const body = merovingian::tests::parse_object(result.response.body);
                // Spec MUST: `duration_ms` is required and an integer.
                auto const* duration = merovingian::tests::int_member(body, "duration_ms");
                REQUIRE(duration != nullptr);
                CHECK(*duration >= 0);
            }

            THEN("the appservice was called once at POST /_matrix/app/v1/ping with its hs_token and the transaction_id")
            {
                auto const calls = mock.requests_to("/_matrix/app/v1/ping");
                // Spec MUST: the homeserver calls POST /_matrix/app/v1/ping on the appservice.
                REQUIRE(calls.size() == 1U);
                CHECK(calls.front().method == "POST");
                // Spec MUST: the homeserver authenticates to the appservice with its hs_token.
                CHECK(calls.front().authorization == "Bearer " + bridge.hs_token());
                // Spec: the ping body is `transaction_id`, "copied directly from the ... ping call".
                auto const sent = merovingian::tests::parse_object(calls.front().body);
                auto const* transaction_id = merovingian::tests::string_member(sent, "transaction_id");
                REQUIRE(transaction_id != nullptr);
                CHECK(*transaction_id == "mautrix-go_1_123");
            }
        }

        WHEN("it pings with no body at all")
        {
            auto const result = ping(runtime, "bridge", bridge.as_token());

            THEN("transaction_id is optional, so this is a 200 and the appservice is sent an object without one")
            {
                // Spec MUST: `transaction_id` is "An optional transaction ID".
                REQUIRE(result.response.status == 200U);
                auto const calls = mock.requests_to("/_matrix/app/v1/ping");
                // Spec MUST: the homeserver calls POST /_matrix/app/v1/ping on the appservice.
                REQUIRE(calls.size() == 1U);
                auto const sent = merovingian::tests::parse_object(calls.front().body);
                CHECK(merovingian::tests::string_member(sent, "transaction_id") == nullptr);
            }
        }

        WHEN("it pings with an empty transaction_id")
        {
            auto const result = ping(runtime, "bridge", bridge.as_token(), R"({"transaction_id":""})");

            THEN("the empty string is passed through as given, not dropped")
            {
                // Spec MUST: "200: The ping was successful."
                REQUIRE(result.response.status == 200U);
                auto const calls = mock.requests_to("/_matrix/app/v1/ping");
                // Spec MUST: the homeserver calls POST /_matrix/app/v1/ping on the appservice.
                REQUIRE(calls.size() == 1U);
                auto const sent = merovingian::tests::parse_object(calls.front().body);
                auto const* transaction_id = merovingian::tests::string_member(sent, "transaction_id");
                // Spec MUST: `transaction_id` is "copied directly from the POST .../ping call".
                REQUIRE(transaction_id != nullptr);
                CHECK(transaction_id->empty());
            }
        }

        WHEN("it pings with a transaction_id that is not a string")
        {
            auto const result = ping(runtime, "bridge", bridge.as_token(), R"({"transaction_id":7})");

            THEN("the request is refused as malformed and the appservice is not called")
            {
                CHECK(result.response.status == 400U);
                CHECK(mock.requests_to("/_matrix/app/v1/ping").empty());
            }
        }
    }
}

// Spec: Application Service API v1.19
// Endpoint / Section: POST /_matrix/client/v1/appservice/{appserviceId}/ping — 403
// URL: ../../docs/matrix-v1.19-spec/application-service-api.md#post_matrixclientv1appserviceappserviceidping
//
// "403: The access token used to authenticate the request doesn't belong to an appservice, or belongs to a
// different appservice than the one in the path. The errcode is M_FORBIDDEN." and "the appservice ID in the
// path must be the same as the appservice whose as_token is being used".
SCENARIO("only the appservice named in the path may ping, with its own as_token", "[appservice][conformance][ping]")
{
    GIVEN("two appservices and an ordinary user")
    {
        auto first = TestAppservice{.id = "first"};
        auto second = TestAppservice{.id = "second"};
        auto first_mock = MockAppservice{};
        auto second_mock = MockAppservice{};
        first.url = first_mock.url();
        second.url = second_mock.url();
        auto started =
            merovingian::homeserver::start_client_server(merovingian::tests::appservice_test_config({first, second}));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const registered = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST",
                      "/_matrix/client/v3/register",
                      {},
                      merovingian::tests::registration_json("alice", "CorrectHorse7!")});
        REQUIRE(registered.response.status == 200U);
        auto const alice = *merovingian::tests::string_member(
            merovingian::tests::parse_object(registered.response.body), "access_token");

        WHEN("an ordinary user's access token pings an appservice")
        {
            auto const result = ping(runtime, "first", alice);

            THEN("403 M_FORBIDDEN and nothing is sent to the appservice")
            {
                CHECK(result.response.status == 403U);
                CHECK(errcode_of(result) == "M_FORBIDDEN");
                CHECK(first_mock.requests().empty());
            }
        }

        WHEN("one appservice's as_token names the other in the path")
        {
            auto const result = ping(runtime, "second", first.as_token());

            THEN("403 M_FORBIDDEN and neither appservice is called")
            {
                CHECK(result.response.status == 403U);
                CHECK(errcode_of(result) == "M_FORBIDDEN");
                CHECK(first_mock.requests().empty());
                CHECK(second_mock.requests().empty());
            }
        }

        WHEN("an appservice id that is registered nowhere is named")
        {
            auto const result = ping(runtime, "nobody", first.as_token());

            THEN("403 M_FORBIDDEN, the same answer as any other mismatch")
            {
                CHECK(result.response.status == 403U);
                CHECK(errcode_of(result) == "M_FORBIDDEN");
            }
        }

        WHEN("no access token is presented")
        {
            auto const result = ping(runtime, "first", {});

            THEN("it is the usual 401 M_MISSING_TOKEN, not a ping")
            {
                CHECK(result.response.status == 401U);
                CHECK(errcode_of(result) == "M_MISSING_TOKEN");
                CHECK(first_mock.requests().empty());
            }
        }
    }
}

// Spec: Application Service API v1.19
// Endpoint / Section: POST /_matrix/client/v1/appservice/{appserviceId}/ping — 400
// URL: ../../docs/matrix-v1.19-spec/application-service-api.md#post_matrixclientv1appserviceappserviceidping
//
// "400: The application service doesn't have a URL configured. The errcode is M_URL_NOT_SET."
SCENARIO("pinging an appservice with no url is 400 M_URL_NOT_SET", "[appservice][conformance][ping]")
{
    GIVEN("an appservice registered with url: null")
    {
        auto bridge = TestAppservice{.id = "quiet"};
        auto started =
            merovingian::homeserver::start_client_server(merovingian::tests::appservice_test_config({bridge}));
        REQUIRE(started.started);

        WHEN("it pings")
        {
            auto const result = ping(started.runtime, "quiet", bridge.as_token());

            THEN("400 M_URL_NOT_SET")
            {
                CHECK(result.response.status == 400U);
                CHECK(errcode_of(result) == "M_URL_NOT_SET");
            }
        }
    }
}

// Spec: Application Service API v1.19
// Endpoint / Section: POST /_matrix/client/v1/appservice/{appserviceId}/ping — 502
// URL: ../../docs/matrix-v1.19-spec/application-service-api.md#post_matrixclientv1appserviceappserviceidping
//
// "502: The application service returned a bad status, or the connection failed. The errcode is
// M_BAD_STATUS or M_CONNECTION_FAILED. For bad statuses, the response may include `status` and `body`
// fields containing the HTTP status code and response body text respectively to aid with debugging."
// The spec's own example is an appservice answering 403 {"errcode": "M_FORBIDDEN"} to a wrong hs_token.
SCENARIO("a ping the appservice rejects is 502 M_BAD_STATUS with its status and body",
         "[appservice][conformance][ping]")
{
    GIVEN("an appservice that answers 403 M_FORBIDDEN, as it would to a wrong hs_token")
    {
        auto bridge = TestAppservice{.id = "bridge"};
        auto mock = MockAppservice{};
        mock.set_answer("/_matrix/app/v1/ping", 403U, R"({"errcode": "M_FORBIDDEN"})");
        bridge.url = mock.url();
        auto started =
            merovingian::homeserver::start_client_server(merovingian::tests::appservice_test_config({bridge}));
        REQUIRE(started.started);

        WHEN("it pings")
        {
            auto const result = ping(started.runtime, "bridge", bridge.as_token());

            THEN("502 M_BAD_STATUS carrying status 403 and the appservice's body text")
            {
                REQUIRE(result.response.status == 502U);
                auto const body = merovingian::tests::parse_object(result.response.body);
                REQUIRE(merovingian::tests::string_member(body, "errcode") != nullptr);
                CHECK(*merovingian::tests::string_member(body, "errcode") == "M_BAD_STATUS");
                auto const* status = merovingian::tests::int_member(body, "status");
                REQUIRE(status != nullptr);
                CHECK(*status == 403);
                auto const* text = merovingian::tests::string_member(body, "body");
                REQUIRE(text != nullptr);
                CHECK(*text == R"({"errcode": "M_FORBIDDEN"})");
                CHECK(merovingian::tests::string_member(body, "error") != nullptr);
            }
        }
    }

    GIVEN("an appservice that answers with a very large error body")
    {
        auto bridge = TestAppservice{.id = "bridge"};
        auto mock = MockAppservice{};
        mock.set_answer("/_matrix/app/v1/ping", 500U, std::string(100000U, 'x'));
        bridge.url = mock.url();
        auto started =
            merovingian::homeserver::start_client_server(merovingian::tests::appservice_test_config({bridge}));
        REQUIRE(started.started);

        WHEN("it pings")
        {
            auto const result = ping(started.runtime, "bridge", bridge.as_token());

            THEN("the body echoed to the caller is bounded")
            {
                // Spec MUST: "502: The application service returned a bad status".
                REQUIRE(result.response.status == 502U);
                auto const body = merovingian::tests::parse_object(result.response.body);
                auto const* text = merovingian::tests::string_member(body, "body");
                REQUIRE(text != nullptr);
                CHECK(text->size() <= 1024U);
            }
        }
    }
}

// Spec: Application Service API v1.19
// Endpoint / Section: POST /_matrix/client/v1/appservice/{appserviceId}/ping — 502 (M_CONNECTION_FAILED)
// URL: ../../docs/matrix-v1.19-spec/application-service-api.md#post_matrixclientv1appserviceappserviceidping
//
// "502: The application service returned a bad status, or the connection failed. The errcode is
// M_BAD_STATUS or M_CONNECTION_FAILED." The "Pinging" section's "Can't connect to appservice" flow
// answers 502 {"errcode": "M_CONNECTION_FAILED"}.
SCENARIO("a ping the homeserver cannot deliver is 502 M_CONNECTION_FAILED", "[appservice][conformance][ping]")
{
    GIVEN("an appservice whose url points at a closed port")
    {
        auto bridge = TestAppservice{.id = "bridge"};
        bridge.url = "http://127.0.0.1:" + std::to_string(closed_port());
        auto started =
            merovingian::homeserver::start_client_server(merovingian::tests::appservice_test_config({bridge}));
        REQUIRE(started.started);

        WHEN("it pings")
        {
            auto const result = ping(started.runtime, "bridge", bridge.as_token());

            THEN("502 M_CONNECTION_FAILED")
            {
                CHECK(result.response.status == 502U);
                CHECK(errcode_of(result) == "M_CONNECTION_FAILED");
            }
        }
    }
}

// Spec: Application Service API v1.19
// Endpoint / Section: POST /_matrix/client/v1/appservice/{appserviceId}/ping — 504
// URL: ../../docs/matrix-v1.19-spec/application-service-api.md#post_matrixclientv1appserviceappserviceidping
//
// "504: The connection to the application service timed out. The errcode is M_CONNECTION_TIMEOUT."
// Project policy, not the spec: the homeserver must not hold runtime.mutex across the call, because the
// request pool shares one lock with every other client and with inbound federation.
SCENARIO("a ping the appservice never answers is 504 M_CONNECTION_TIMEOUT and holds no runtime lock",
         "[appservice][conformance][ping][security]")
{
    GIVEN("an appservice that accepts the request and never answers, with a two second timeout")
    {
        auto bridge = TestAppservice{.id = "bridge"};
        auto mock = MockAppservice{};
        mock.go_silent(true);
        bridge.url = mock.url();
        auto config = merovingian::tests::appservice_test_config({bridge});
        config.appservice().connect_timeout_seconds = 1U;
        config.appservice().total_timeout_seconds = 2U;
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;

        WHEN("it pings, and another thread asks for the runtime lock while the ping is in flight")
        {
            auto result = merovingian::homeserver::DispatchResult{};
            auto lock_was_free = false;
            {
                auto threads = merovingian::tests::JoiningThreads{};
                threads.emplace_back([&]() {
                    result = ping(runtime, "bridge", bridge.as_token());
                });
                REQUIRE(mock.wait_for_requests(1U, 3s));
                if (runtime.homeserver.mutex.try_lock())
                {
                    lock_was_free = true;
                    runtime.homeserver.mutex.unlock();
                }
            }

            THEN("the lock was free during the call")
            {
                // Spec/ADR: runtime.mutex is released across every blocking network call.
                CHECK(lock_was_free);
            }

            THEN("the answer is 504 M_CONNECTION_TIMEOUT")
            {
                CHECK(result.response.status == 504U);
                CHECK(errcode_of(result) == "M_CONNECTION_TIMEOUT");
            }
        }
    }
}

// Spec: Application Service API v1.19
// Endpoint / Section: POST /_matrix/client/v1/appservice/{appserviceId}/ping — rate limiting
// URL: ../../docs/matrix-v1.19-spec/application-service-api.md#post_matrixclientv1appserviceappserviceidping
//
// The endpoint is documented "Rate-limited: No".
SCENARIO("repeated pings are not rate limited", "[appservice][conformance][ping]")
{
    GIVEN("a working appservice and a burst of pings from one address")
    {
        auto bridge = TestAppservice{.id = "bridge"};
        auto mock = MockAppservice{};
        bridge.url = mock.url();
        auto started =
            merovingian::homeserver::start_client_server(merovingian::tests::appservice_test_config({bridge}));
        REQUIRE(started.started);

        WHEN("fifty pings are made")
        {
            auto statuses = std::vector<std::uint16_t>{};
            for (auto index = 0; index < 50; ++index)
            {
                statuses.push_back(ping(started.runtime, "bridge", bridge.as_token()).response.status);
            }

            THEN("every one is answered 200")
            {
                CHECK(std::ranges::all_of(statuses, [](std::uint16_t status) {
                    return status == 200U;
                }));
            }
        }
    }
}
