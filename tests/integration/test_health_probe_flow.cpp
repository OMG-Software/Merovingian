// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// GET /_merovingian/health (ADR-0479): an unauthenticated liveness and readiness probe for load balancers. It is
// answered by the connection handler before the request reaches the dispatcher, so it takes no lock a slow request
// can hold, and it reveals nothing but its fixed body. A choice of this server, so an integration flow.

#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "bounded_connect.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/http_server.hpp"
#include "merovingian/homeserver/runtime_mutex.hpp"
#include "merovingian/net/shutdown_signal.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "merovingian/net/thread_pool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace
{

[[nodiscard]] auto probe_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
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

// One request on a fresh connection; the answer up to close, or empty if nothing came within five seconds.
[[nodiscard]] auto exchange(std::uint16_t port, std::string_view request) -> std::string
{
    auto const fd = ::socket(AF_INET, SOCK_STREAM, 0);
    REQUIRE(fd >= 0);
    auto address = sockaddr_in{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    REQUIRE(merovingian::tests::connect_within(fd, *reinterpret_cast<sockaddr const*>(&address), sizeof(address)));
    auto const timeout = timeval{5, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    REQUIRE(::send(fd, request.data(), request.size(), 0) == static_cast<ssize_t>(request.size()));
    auto output = std::string{};
    auto buffer = std::array<char, 4096U>{};
    while (true)
    {
        auto const received = ::recv(fd, buffer.data(), buffer.size(), 0);
        if (received <= 0)
        {
            break;
        }
        output.append(buffer.data(), static_cast<std::size_t>(received));
    }
    ::close(fd);
    return output;
}

} // namespace

// Endpoint: GET /_merovingian/health. Not in the Matrix spec: the project's own probe.
SCENARIO("GET /_merovingian/health answers 200 with a fixed body and no credentials",
         "[homeserver][http][health][integration]")
{
    GIVEN("a started server on a loopback listener")
    {
        auto runtime_result = merovingian::homeserver::start_client_server(probe_config());
        REQUIRE(runtime_result.started);
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        auto shutdown = merovingian::net::ShutdownSignal{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{4U};
        auto server_thread = std::thread{[&]() {
            merovingian::homeserver::serve_http(acceptor, runtime, shutdown, stats,
                                                merovingian::homeserver::HttpDispatchMode::client_server, pool);
        }};

        WHEN("an unauthenticated client asks for the probe")
        {
            auto const response =
                exchange(port, "GET /_merovingian/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");

            THEN("the answer is 200 with the fixed body and nothing about the server")
            {
                REQUIRE(response.starts_with("HTTP/1.1 200"));
                REQUIRE(response.ends_with("\r\n\r\nok"));
                REQUIRE(response.find("example.org") == std::string::npos);
                REQUIRE(response.find("version") == std::string::npos);
                REQUIRE(response.find("Version") == std::string::npos);
            }
        }

        WHEN("a slow request holds the runtime lock and the probe is asked meanwhile")
        {
            auto response = std::string{};
            {
                auto const held = std::unique_lock<merovingian::homeserver::RuntimeMutex>{runtime.homeserver.mutex};
                response =
                    exchange(port, "GET /_merovingian/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
            }

            THEN("it is still answered 200, because it takes no lock")
            {
                REQUIRE(response.starts_with("HTTP/1.1 200"));
            }
        }

        WHEN("a method other than GET names the probe path")
        {
            auto const response = exchange(port, "POST /_merovingian/health HTTP/1.1\r\nHost: "
                                                 "localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");

            THEN("it is not the probe")
            {
                REQUIRE_FALSE(response.starts_with("HTTP/1.1 200"));
            }
        }

        shutdown.fire();
        server_thread.join();
        pool.request_stop();
    }
}

SCENARIO("The health probe answers 503 with a fixed body when the server is not serving", "[homeserver][http][health]")
{
    GIVEN("the probe's answer for a server that has stopped accepting requests")
    {
        WHEN("it is built")
        {
            auto const serving = merovingian::homeserver::health_probe_response(true);
            auto const stopping = merovingian::homeserver::health_probe_response(false);

            THEN("serving is 200 ok and stopping is 503 with a different fixed body that names nothing")
            {
                REQUIRE(serving.status == 200U);
                REQUIRE(serving.body == "ok");
                REQUIRE(stopping.status == 503U);
                REQUIRE(stopping.body == "unavailable");
            }
        }
    }
}

// A connection served with no dispatcher (serve_one_http_connection, which tests and embeds use) has no dispatcher
// to ask whether the server is running; the probe must answer, as serving, and not dereference it.
SCENARIO("The health probe is answered on a connection served without a dispatcher", "[homeserver][http][health]")
{
    GIVEN("a started runtime and a connected socket pair")
    {
        auto runtime_result = merovingian::homeserver::start_client_server(probe_config());
        REQUIRE(runtime_result.started);
        auto runtime = std::move(runtime_result.runtime);
        auto stats = merovingian::homeserver::HttpServeStats{};
        int fds[2]{-1, -1};
        REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) == 0);
        auto const timeout = timeval{5, 0};
        ::setsockopt(fds[0], SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
        auto const request =
            std::string_view{"GET /_merovingian/health HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"};
        REQUIRE(::send(fds[0], request.data(), request.size(), 0) == static_cast<ssize_t>(request.size()));

        WHEN("the one connection is served")
        {
            std::ignore = merovingian::homeserver::serve_one_http_connection(
                fds[1], runtime, stats, merovingian::homeserver::HttpDispatchMode::client_server, nullptr, "127.0.0.1",
                nullptr);
            ::shutdown(fds[1], SHUT_WR);
            auto response = std::string{};
            auto buffer = std::array<char, 4096U>{};
            while (true)
            {
                auto const received = ::recv(fds[0], buffer.data(), buffer.size(), 0);
                if (received <= 0)
                {
                    break;
                }
                response.append(buffer.data(), static_cast<std::size_t>(received));
            }
            ::close(fds[0]);
            ::close(fds[1]);

            THEN("it answers 200 ok")
            {
                REQUIRE(response.starts_with("HTTP/1.1 200"));
                REQUIRE(response.ends_with("\r\n\r\nok"));
            }
        }
    }
}
