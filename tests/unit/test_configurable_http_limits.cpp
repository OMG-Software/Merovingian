// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/homeserver/http_server.hpp"
#include "merovingian/http/request.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <string>
#include <thread>
#include <tuple>

#include <sys/socket.h>
#include <unistd.h>

using merovingian::homeserver::ClientServerRuntime;
using merovingian::homeserver::HttpDispatchMode;

namespace
{

[[nodiscard]] auto federation_request(ClientServerRuntime& runtime, std::uint64_t body_bytes, bool send_body = true)
    -> std::string
{
    auto fds = std::array<int, 2>{-1, -1};
    REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds.data()) == 0);
    auto server_end = merovingian::core::FileDescriptor{fds[0]};
    auto client_end = merovingian::core::FileDescriptor{fds[1]};
    auto stats = merovingian::homeserver::HttpServeStats{};
    auto server = std::jthread{[&runtime, &stats, fd = std::move(server_end)]() mutable {
        std::ignore =
            merovingian::homeserver::serve_one_http_connection(fd.get(), runtime, stats, HttpDispatchMode::federation);
        fd.reset();
    }};

    auto request = std::string{"PUT /_matrix/federation/v1/send/txn HTTP/1.1\r\nHost: local\r\nContent-Length: "};
    request.append(std::to_string(body_bytes));
    request.append("\r\nConnection: close\r\n\r\n");
    if (send_body)
    {
        request.append(static_cast<std::size_t>(body_bytes), 'x');
    }
    auto offset = std::size_t{0U};
    while (offset < request.size())
    {
        auto const written = ::send(client_end.get(), request.data() + offset, request.size() - offset, 0);
        REQUIRE(written > 0);
        offset += static_cast<std::size_t>(written);
    }
    REQUIRE(::shutdown(client_end.get(), SHUT_WR) == 0);

    auto response = std::string{};
    auto chunk = std::array<char, 1024U>{};
    for (auto bytes_read = ::recv(client_end.get(), chunk.data(), chunk.size(), 0); bytes_read > 0;
         bytes_read = ::recv(client_end.get(), chunk.data(), chunk.size(), 0))
    {
        response.append(chunk.data(), static_cast<std::size_t>(bytes_read));
    }
    server.join();
    return response;
}

[[nodiscard]] auto response_status(std::string const& response) -> std::uint16_t
{
    if (response.size() < 12U)
    {
        return 0U;
    }
    return static_cast<std::uint16_t>((response[9] - '0') * 100 + (response[10] - '0') * 10 + response[11] - '0');
}

} // namespace

SCENARIO("Configured HTTP head limits are used by the request parser", "[http][limits][config]")
{
    GIVEN("server HTTP limits with smaller start-line, header-byte and header-count budgets")
    {
        auto runtime = ClientServerRuntime{};
        auto& config = runtime.homeserver.config.server().http;
        config.max_start_line_bytes = 24U;
        config.max_header_bytes = 32U;
        config.max_header_count = 1U;
        auto const limits = merovingian::homeserver::http_request_limits_for(
            runtime, HttpDispatchMode::client_server, "GET", "/_matrix/client/v3/account/whoami");

        WHEN("request heads cross one configured bound at a time")
        {
            auto const long_line =
                merovingian::http::parse_request_head("GET /_matrix/client/v3/account/whoami HTTP/1.1\r\n\r\n", limits);
            auto const oversized_headers = merovingian::http::parse_request_head(
                "GET / HTTP/1.1\r\nX: 1234567890123456789012345678901234567890\r\n\r\n", limits);
            auto const too_many_headers =
                merovingian::http::parse_request_head("GET / HTTP/1.1\r\nA: b\r\nB: c\r\n\r\n", limits);

            THEN("the parser reports the configured request-head failures")
            {
                REQUIRE(long_line.error == merovingian::http::RequestErrorCode::start_line_too_large);
                REQUIRE(oversized_headers.error == merovingian::http::RequestErrorCode::headers_too_large);
                REQUIRE(too_many_headers.error == merovingian::http::RequestErrorCode::too_many_headers);
            }
        }
    }
}

SCENARIO("Federation send bodies use the configured transaction cap at the transport boundary",
         "[http][limits][federation][regression]")
{
    GIVEN("a federation transaction cap above the ordinary HTTP body limit")
    {
        auto runtime = ClientServerRuntime{};
        runtime.homeserver.config.security().federation.max_transaction_size = "2MiB";

        WHEN("a send request body exceeds the ordinary one-MiB HTTP limit but fits the transaction cap")
        {
            auto const response = federation_request(runtime, 1U * 1024U * 1024U + 1U);

            THEN("the transport reads it and proceeds to federation handling")
            {
                REQUIRE(response_status(response) >= 200U);
                REQUIRE(response_status(response) <= 599U);
                REQUIRE(response_status(response) != 413U);
            }
        }

        WHEN("the declared send body exceeds the configured transaction cap")
        {
            auto const response = federation_request(runtime, 2U * 1024U * 1024U + 1U, false);

            THEN("the transport rejects it before reading the body")
            {
                REQUIRE(response_status(response) == 413U);
            }
        }
    }
}

SCENARIO("Configured request body limits remain separate from federation transaction limits", "[http][limits][config]")
{
    GIVEN("a configured ordinary body size and federation transaction size")
    {
        auto runtime = ClientServerRuntime{};
        runtime.homeserver.config.server().http.max_body_size = "2MiB";
        runtime.homeserver.config.security().federation.max_transaction_size = "6MiB";

        WHEN("client-server and federation send limits are resolved")
        {
            auto const client = merovingian::homeserver::http_request_limits_for(
                runtime, HttpDispatchMode::client_server, "POST", "/_matrix/client/v3/room_keys/upload");
            auto const federation_send = merovingian::homeserver::http_request_limits_for(
                runtime, HttpDispatchMode::federation, "PUT", "/_matrix/federation/v1/send/txn");
            auto const other_federation = merovingian::homeserver::http_request_limits_for(
                runtime, HttpDispatchMode::federation, "GET", "/_matrix/federation/v1/version");

            THEN("ordinary requests use the HTTP cap and federation send uses its transaction cap")
            {
                REQUIRE(client.max_body_bytes == 2U * 1024U * 1024U);
                REQUIRE(federation_send.max_body_bytes == 6U * 1024U * 1024U);
                REQUIRE(other_federation.max_body_bytes == 2U * 1024U * 1024U);
            }
        }
    }
}

SCENARIO("Sync admission follows configured caps but never exceeds its pool size", "[http][sync][limits][config]")
{
    GIVEN("sync limits configured above and below a pool's worker count")
    {
        auto config = merovingian::config::HttpTransportConfig{};

        WHEN("the pool is smaller than the configured global wait cap")
        {
            auto const caps = merovingian::homeserver::sync_admission_caps(config, 32U);

            THEN("global admission is bounded by the actual worker pool and per-user/device caps are retained")
            {
                REQUIRE(caps.global == 32U);
                REQUIRE(caps.per_user == 4U);
                REQUIRE(caps.per_device == 2U);
            }
        }

        WHEN("the pool is larger than the configured global wait cap")
        {
            auto const caps = merovingian::homeserver::sync_admission_caps(config, 256U);

            THEN("the configured admission limit is applied")
            {
                REQUIRE(caps.global == 128U);
            }
        }
    }
}
