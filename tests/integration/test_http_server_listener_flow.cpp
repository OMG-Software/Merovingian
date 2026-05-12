// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/config/config.hpp>
#include <merovingian/homeserver/http_server.hpp>
#include <merovingian/homeserver/vertical_slice.hpp>
#include <merovingian/net/shutdown_signal.hpp>
#include <merovingian/net/tcp_acceptor.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    security.registration.enabled = true;
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
    };
}

[[nodiscard]] auto connect_loopback(std::uint16_t port) -> int
{
    auto const fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        return -1;
    }
    auto address = sockaddr_in{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (::connect(fd, reinterpret_cast<sockaddr const*>(&address), sizeof(address)) != 0)
    {
        ::close(fd);
        return -1;
    }
    return fd;
}

auto send_all(int fd, std::string_view data) -> bool
{
    auto remaining = data;
    while (!remaining.empty())
    {
        auto const sent = ::send(fd, remaining.data(), remaining.size(), 0);
        if (sent <= 0)
        {
            return false;
        }
        remaining.remove_prefix(static_cast<std::size_t>(sent));
    }
    return true;
}

[[nodiscard]] auto receive_until_close(int fd) -> std::string
{
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
    return output;
}

} // namespace

SCENARIO("merovingian-server accepts an HTTP request and returns the router's response over a TCP socket",
         "[homeserver][http][listener][integration]")
{
    GIVEN("a started runtime and a TCP acceptor bound to an ephemeral loopback port")
    {
        auto const config = registration_enabled_config();
        auto runtime_result = merovingian::homeserver::start_runtime(config);
        REQUIRE(runtime_result.started);

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto shutdown = merovingian::net::ShutdownSignal{};
        auto runtime_lock = std::mutex{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        auto runtime = std::move(runtime_result.runtime);

        WHEN("a client sends an HTTP/1.1 request to an unknown route")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_http(acceptor, runtime, runtime_lock, shutdown, stats);
            }};

            auto const client_fd = connect_loopback(port);
            REQUIRE(client_fd >= 0);

            auto const request = std::string{"GET /no-such-route HTTP/1.1\r\nHost: localhost\r\n\r\n"};
            REQUIRE(send_all(client_fd, request));

            auto const response = receive_until_close(client_fd);
            ::close(client_fd);

            shutdown.fire();
            server_thread.join();

            THEN("the response status line and router body are returned and the connection closes")
            {
                REQUIRE(response.starts_with("HTTP/1.1 404"));
                REQUIRE(response.find("route not found") != std::string::npos);
                REQUIRE(stats.accepted_connections >= 1U);
                REQUIRE(stats.completed_requests >= 1U);
            }
        }
    }
}

SCENARIO("merovingian-server rejects an oversized request head with a 4xx status and stays alive",
         "[homeserver][http][listener][integration]")
{
    GIVEN("a started runtime and an active HTTP listener")
    {
        auto const config = registration_enabled_config();
        auto runtime_result = merovingian::homeserver::start_runtime(config);
        REQUIRE(runtime_result.started);

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();

        auto shutdown = merovingian::net::ShutdownSignal{};
        auto runtime_lock = std::mutex{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        auto runtime = std::move(runtime_result.runtime);

        auto server_thread = std::thread{[&]() {
            merovingian::homeserver::serve_http(acceptor, runtime, runtime_lock, shutdown, stats);
        }};

        WHEN("a client sends a request with a header that exceeds the configured limit")
        {
            auto const oversize_value = std::string(40000U, 'a');
            auto const oversize_request = "GET / HTTP/1.1\r\nHost: localhost\r\nX-Huge: " + oversize_value + "\r\n\r\n";

            auto const client_fd = connect_loopback(port);
            REQUIRE(client_fd >= 0);
            send_all(client_fd, oversize_request);
            auto const response = receive_until_close(client_fd);
            ::close(client_fd);

            // A small follow-up request should still succeed against the same server.
            auto const follow_fd = connect_loopback(port);
            REQUIRE(follow_fd >= 0);
            REQUIRE(send_all(follow_fd, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"));
            auto const follow_response = receive_until_close(follow_fd);
            ::close(follow_fd);

            shutdown.fire();
            server_thread.join();

            THEN("the oversized request gets a 4xx and the listener continues to serve")
            {
                REQUIRE_FALSE(response.empty());
                REQUIRE(response.starts_with("HTTP/1.1 4"));
                REQUIRE_FALSE(follow_response.empty());
                REQUIRE(follow_response.starts_with("HTTP/1.1 "));
                REQUIRE(stats.rejected_requests >= 1U);
            }
        }
    }
}
