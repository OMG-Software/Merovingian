// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/http/connection_guard.hpp"
#include "merovingian/http/keep_alive.hpp"
#include "merovingian/http/request.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>

SCENARIO("HTTP keep-alive policy validates operator-tunable bounds", "[http][keep-alive]")
{
    GIVEN("the default keep-alive policy")
    {
        auto const policy = merovingian::http::KeepAlivePolicy{};

        WHEN("the policy is validated")
        {
            auto const valid = merovingian::http::keep_alive_policy_is_valid(policy);

            THEN("the defaults are accepted and are persistent-connection defaults")
            {
                REQUIRE(valid);
                REQUIRE(policy.enabled);
                REQUIRE(policy.idle_timeout_seconds == 15U);
                REQUIRE(policy.max_connections == 8U);
            }
        }
    }

    GIVEN("policies with out-of-range bounds")
    {
        auto zero_idle = merovingian::http::KeepAlivePolicy{};
        zero_idle.idle_timeout_seconds = 0U;
        auto idle_over_cap = merovingian::http::KeepAlivePolicy{};
        idle_over_cap.idle_timeout_seconds = 301U;
        auto zero_max = merovingian::http::KeepAlivePolicy{};
        zero_max.max_connections = 0U;
        auto max_over_cap = merovingian::http::KeepAlivePolicy{};
        max_over_cap.max_connections = 4097U;

        WHEN("the policies are validated")
        {
            THEN("each out-of-range policy is rejected")
            {
                REQUIRE_FALSE(merovingian::http::keep_alive_policy_is_valid(zero_idle));
                REQUIRE_FALSE(merovingian::http::keep_alive_policy_is_valid(idle_over_cap));
                REQUIRE_FALSE(merovingian::http::keep_alive_policy_is_valid(zero_max));
                REQUIRE_FALSE(merovingian::http::keep_alive_policy_is_valid(max_over_cap));
            }
        }
    }
}

SCENARIO("HTTP Connection header tokens are matched case-insensitively in comma lists", "[http][keep-alive]")
{
    GIVEN("connection header values as sent by real clients")
    {
        WHEN("the header values are scanned for the close and keep-alive tokens")
        {
            THEN("token matching is case-insensitive and list aware")
            {
                REQUIRE(merovingian::http::connection_header_has_token("close", "close"));
                REQUIRE(merovingian::http::connection_header_has_token("Close", "close"));
                REQUIRE(merovingian::http::connection_header_has_token("keep-alive", "keep-alive"));
                REQUIRE(merovingian::http::connection_header_has_token("Keep-Alive", "keep-alive"));
                REQUIRE(merovingian::http::connection_header_has_token("keep-alive, Upgrade", "keep-alive"));
                REQUIRE(merovingian::http::connection_header_has_token("Upgrade, close", "close"));
                REQUIRE_FALSE(merovingian::http::connection_header_has_token("keep-alive", "close"));
                REQUIRE_FALSE(merovingian::http::connection_header_has_token("", "close"));
                REQUIRE_FALSE(merovingian::http::connection_header_has_token("keep-alive", "close-alive"));
            }
        }
    }
}

SCENARIO("HTTP/1.1 requests default to keep-alive and honour Connection close", "[http][keep-alive]")
{
    GIVEN("HTTP/1.1 request heads with and without a Connection header")
    {
        WHEN("the per-request connection preference is decided")
        {
            auto const no_header =
                merovingian::http::connection_preference_for_request(merovingian::http::HttpVersion::http_1_1, "");
            auto const keep_alive_header = merovingian::http::connection_preference_for_request(
                merovingian::http::HttpVersion::http_1_1, "keep-alive");
            auto const close_header =
                merovingian::http::connection_preference_for_request(merovingian::http::HttpVersion::http_1_1, "close");

            THEN("HTTP/1.1 defaults to keep-alive unless the client asks to close")
            {
                REQUIRE(no_header == merovingian::http::ConnectionPreference::keep_alive);
                REQUIRE(keep_alive_header == merovingian::http::ConnectionPreference::keep_alive);
                REQUIRE(close_header == merovingian::http::ConnectionPreference::close);
            }
        }
    }
}

SCENARIO("HTTP/1.0 requests default to close and keep alive only on explicit request", "[http][keep-alive]")
{
    GIVEN("HTTP/1.0 request heads with and without a Connection header")
    {
        WHEN("the per-request connection preference is decided")
        {
            auto const no_header =
                merovingian::http::connection_preference_for_request(merovingian::http::HttpVersion::http_1_0, "");
            auto const keep_alive_header = merovingian::http::connection_preference_for_request(
                merovingian::http::HttpVersion::http_1_0, "keep-alive");
            auto const close_header =
                merovingian::http::connection_preference_for_request(merovingian::http::HttpVersion::http_1_0, "close");

            THEN("HTTP/1.0 defaults to close unless the client explicitly asks for keep-alive")
            {
                REQUIRE(no_header == merovingian::http::ConnectionPreference::close);
                REQUIRE(keep_alive_header == merovingian::http::ConnectionPreference::keep_alive);
                REQUIRE(close_header == merovingian::http::ConnectionPreference::close);
            }
        }
    }
}

SCENARIO("The response connection preference composes the client request with the operator policy",
         "[http][keep-alive]")
{
    GIVEN("the default keep-alive policy and an HTTP/1.1 request without a Connection header")
    {
        auto const policy = merovingian::http::KeepAlivePolicy{};

        WHEN("the server decides whether to hold the connection open, with no connections parked")
        {
            auto const decision = merovingian::http::connection_preference_for_response(
                merovingian::http::HttpVersion::http_1_1, "", policy, 0U);

            THEN("the connection is held open")
            {
                REQUIRE(decision == merovingian::http::ConnectionPreference::keep_alive);
            }
        }

        WHEN("the operator has disabled keep-alive")
        {
            auto disabled = merovingian::http::KeepAlivePolicy{};
            disabled.enabled = false;
            auto const decision = merovingian::http::connection_preference_for_response(
                merovingian::http::HttpVersion::http_1_1, "keep-alive", disabled, 0U);

            THEN("every response closes the connection")
            {
                REQUIRE(decision == merovingian::http::ConnectionPreference::close);
            }
        }

        WHEN("the parked-connection cap is already reached")
        {
            auto capped = merovingian::http::KeepAlivePolicy{};
            capped.max_connections = 2U;
            auto const decision = merovingian::http::connection_preference_for_response(
                merovingian::http::HttpVersion::http_1_1, "", capped, 2U);

            THEN("the response closes the connection instead of parking another one")
            {
                REQUIRE(decision == merovingian::http::ConnectionPreference::close);
            }
        }

        WHEN("the client asked to close")
        {
            auto const decision = merovingian::http::connection_preference_for_response(
                merovingian::http::HttpVersion::http_1_1, "close", policy, 0U);

            THEN("the client's close request wins over the operator policy")
            {
                REQUIRE(decision == merovingian::http::ConnectionPreference::close);
            }
        }
    }
}

SCENARIO("The request head parser records the HTTP version for the keep-alive decision", "[http][keep-alive]")
{
    GIVEN("HTTP/1.1 and HTTP/1.0 request heads")
    {
        auto constexpr http11_input = "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n";
        auto constexpr http10_input = "GET / HTTP/1.0\r\nHost: example.org\r\n\r\n";
        auto constexpr http2_input = "GET / HTTP/2.0\r\nHost: example.org\r\n\r\n";

        WHEN("the request heads are parsed")
        {
            auto const http11 = merovingian::http::parse_request_head(http11_input);
            auto const http10 = merovingian::http::parse_request_head(http10_input);
            auto const http2 = merovingian::http::parse_request_head(http2_input);

            THEN("HTTP/1.1 and HTTP/1.0 are parsed with their version recorded and other versions are rejected")
            {
                REQUIRE(http11.error == merovingian::http::RequestErrorCode::none);
                REQUIRE(http11.request.version == merovingian::http::HttpVersion::http_1_1);
                REQUIRE(http10.error == merovingian::http::RequestErrorCode::none);
                REQUIRE(http10.request.version == merovingian::http::HttpVersion::http_1_0);
                REQUIRE(http2.error == merovingian::http::RequestErrorCode::malformed_request_line);
            }
        }
    }
}

SCENARIO("The connection guard distinguishes an idle keep-alive connection from a slow mid-request client",
         "[http][keep-alive][slowloris]")
{
    GIVEN("the default slowloris and keep-alive policies")
    {
        auto const slowloris = merovingian::http::SlowlorisPolicy{};
        auto const keep_alive = merovingian::http::KeepAlivePolicy{};

        WHEN("an idle keep-alive connection and a slow mid-request client are evaluated at 10 elapsed seconds")
        {
            // 10 seconds with zero bytes: well past the slowloris grace period
            // (5 s) and far below its 64 bytes/second rate — a mid-request
            // client making this little progress is a slowloris and must be
            // closed. The same sample evaluated on an idle connection (no
            // request in flight, waiting for the next one) is legitimate
            // keep-alive behaviour and must NOT be killed as slow.
            auto const idle_verdict = merovingian::http::connection_should_close(
                merovingian::http::ConnectionPhase::awaiting_request, {0U, 10U}, slowloris, keep_alive);
            auto const mid_request_verdict = merovingian::http::connection_should_close(
                merovingian::http::ConnectionPhase::reading_request, {0U, 10U}, slowloris, keep_alive);

            THEN("only the mid-request client is closed")
            {
                REQUIRE_FALSE(idle_verdict);
                REQUIRE(mid_request_verdict);
            }
        }

        WHEN("the idle keep-alive window expires")
        {
            auto const idle_expired = merovingian::http::connection_should_close(
                merovingian::http::ConnectionPhase::awaiting_request, {0U, 16U}, slowloris, keep_alive);
            auto const idle_within_window = merovingian::http::connection_should_close(
                merovingian::http::ConnectionPhase::awaiting_request, {0U, 15U}, slowloris, keep_alive);

            THEN("the idle connection is closed once the idle window passes")
            {
                REQUIRE(idle_expired);
                REQUIRE_FALSE(idle_within_window);
            }
        }
    }
}