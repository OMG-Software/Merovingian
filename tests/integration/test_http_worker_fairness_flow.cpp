// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// Audit findings HTTP-1 and HTTP-8 (ADR-0077): one client must not be able to
// hold every worker of the main request pool, whether by keeping connections
// alive, trickling request bodies, opening connections and saying nothing, or
// declaring a huge unauthenticated upload; and a kept-alive connection is closed
// after a request-count or lifetime cap. Every scenario runs a real listener on
// loopback. "Another client" connects from 127.0.0.2; a host without that
// loopback alias skips the scenario.
//
// Tags: [http-1] [http-8] [integration].

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "merovingian/canonicaljson/parser.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/http_server.hpp"
#include "merovingian/net/shutdown_signal.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "merovingian/net/thread_pool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace
{

using namespace std::chrono_literals;
using merovingian::homeserver::HttpDispatchMode;
using merovingian::homeserver::HttpServeTuning;

constexpr auto pool_size = std::size_t{4U};

[[nodiscard]] auto base_config() -> merovingian::config::Config
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

// A connected client socket, closed on scope exit.
class ClientSocket final
{
public:
    ClientSocket() = default;
    explicit ClientSocket(int fd) noexcept
        : m_fd{fd}
    {
    }
    ClientSocket(ClientSocket const&) = delete;
    auto operator=(ClientSocket const&) -> ClientSocket& = delete;
    ClientSocket(ClientSocket&& other) noexcept
        : m_fd{std::exchange(other.m_fd, -1)}
    {
    }
    auto operator=(ClientSocket&& other) noexcept -> ClientSocket&
    {
        if (this != &other)
        {
            reset();
            m_fd = std::exchange(other.m_fd, -1);
        }
        return *this;
    }
    ~ClientSocket()
    {
        reset();
    }
    [[nodiscard]] auto fd() const noexcept -> int
    {
        return m_fd;
    }
    [[nodiscard]] auto valid() const noexcept -> bool
    {
        return m_fd >= 0;
    }
    auto reset() noexcept -> void
    {
        if (m_fd >= 0)
        {
            ::close(m_fd);
            m_fd = -1;
        }
    }

private:
    int m_fd{-1};
};

enum class SourceConnect : std::uint8_t
{
    connected,
    source_unavailable,
    failed,
};

// Connects to 127.0.0.1:port from the loopback address `source`.
[[nodiscard]] auto connect_from(char const* source, std::uint16_t port) -> std::pair<SourceConnect, ClientSocket>
{
    auto socket = ClientSocket{::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)};
    if (!socket.valid())
    {
        return {SourceConnect::failed, ClientSocket{}};
    }
    auto local = sockaddr_in{};
    local.sin_family = AF_INET;
    local.sin_port = 0U;
    if (::inet_pton(AF_INET, source, &local.sin_addr) != 1)
    {
        return {SourceConnect::failed, ClientSocket{}};
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (::bind(socket.fd(), reinterpret_cast<sockaddr const*>(&local), sizeof(local)) != 0)
    {
        return {errno == EADDRNOTAVAIL ? SourceConnect::source_unavailable : SourceConnect::failed, ClientSocket{}};
    }
    auto remote = sockaddr_in{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(port);
    remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (::connect(socket.fd(), reinterpret_cast<sockaddr const*>(&remote), sizeof(remote)) != 0)
    {
        return {SourceConnect::failed, ClientSocket{}};
    }
    return {SourceConnect::connected, std::move(socket)};
}

[[nodiscard]] auto connect_main(std::uint16_t port) -> ClientSocket
{
    auto [status, socket] = connect_from("127.0.0.1", port);
    REQUIRE(status == SourceConnect::connected);
    return std::move(socket);
}

auto send_all(int fd, std::string_view data) -> bool
{
    while (!data.empty())
    {
        auto const sent = ::send(fd, data.data(), data.size(), MSG_NOSIGNAL);
        if (sent <= 0)
        {
            return false;
        }
        data.remove_prefix(static_cast<std::size_t>(sent));
    }
    return true;
}

// Reads one Content-Length framed response, bounded by `within`. Returns what
// arrived (possibly partial or empty) when the peer closes or time runs out.
[[nodiscard]] auto receive_response(int fd, std::chrono::milliseconds within = 10000ms) -> std::string
{
    auto const deadline = std::chrono::steady_clock::now() + within;
    auto pending = std::string{};
    auto buffer = std::array<char, 4096U>{};
    while (true)
    {
        auto const head_end = pending.find("\r\n\r\n");
        if (head_end != std::string::npos)
        {
            auto const header = pending.find("\r\nContent-Length: ");
            if (header != std::string::npos && header < head_end)
            {
                auto const digits = header + 18U;
                auto length = std::size_t{0U};
                for (auto index = digits; index < pending.size() && pending[index] >= '0' && pending[index] <= '9';
                     ++index)
                {
                    length = (length * 10U) + static_cast<std::size_t>(pending[index] - '0');
                }
                if (pending.size() >= head_end + 4U + length)
                {
                    return pending.substr(0U, head_end + 4U + length);
                }
            }
        }
        auto const remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        if (remaining.count() <= 0)
        {
            return pending;
        }
        auto entry = pollfd{};
        entry.fd = fd;
        entry.events = POLLIN;
        if (::poll(&entry, 1U, static_cast<int>(remaining.count())) <= 0)
        {
            return pending;
        }
        auto const received = ::recv(fd, buffer.data(), buffer.size(), 0);
        if (received <= 0)
        {
            return pending;
        }
        pending.append(buffer.data(), static_cast<std::size_t>(received));
    }
}

// True when the server has closed the connection (EOF), draining any response
// bytes into `collected` first. Never blocks.
[[nodiscard]] auto closed_now(int fd, std::string& collected) -> bool
{
    auto buffer = std::array<char, 1024U>{};
    while (true)
    {
        auto const received = ::recv(fd, buffer.data(), buffer.size(), MSG_DONTWAIT);
        if (received == 0)
        {
            return true;
        }
        if (received < 0)
        {
            return errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR;
        }
        collected.append(buffer.data(), static_cast<std::size_t>(received));
    }
}

// Waits until the server closes the connection, collecting what it sent.
[[nodiscard]] auto closed_within(int fd, std::chrono::milliseconds within, std::string& collected) -> bool
{
    auto const deadline = std::chrono::steady_clock::now() + within;
    while (true)
    {
        if (closed_now(fd, collected))
        {
            return true;
        }
        auto const remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        if (remaining.count() <= 0)
        {
            return false;
        }
        auto entry = pollfd{};
        entry.fd = fd;
        entry.events = POLLIN;
        std::ignore = ::poll(&entry, 1U, static_cast<int>(remaining.count()));
    }
}

constexpr auto versions_request = std::string_view{"GET /_matrix/client/versions HTTP/1.1\r\nHost: localhost\r\n\r\n"};

// Sends one request on a fresh connection from `source` and times the answer.
struct TimedResponse final
{
    SourceConnect status{SourceConnect::failed};
    std::string response{};
    std::chrono::milliseconds elapsed{0};
};

[[nodiscard]] auto timed_request_from(char const* source, std::uint16_t port) -> TimedResponse
{
    auto const started = std::chrono::steady_clock::now();
    auto [status, socket] = connect_from(source, port);
    if (status != SourceConnect::connected)
    {
        return {status, {}, 0ms};
    }
    std::ignore = send_all(socket.fd(), versions_request);
    auto response = receive_response(socket.fd());
    return {status, std::move(response),
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started)};
}

// A listener on an ephemeral loopback port, served until destruction. Stops
// the listener and the pools on every exit path, including a failed REQUIRE.
class Listener final
{
public:
    Listener(merovingian::homeserver::ClientServerRuntime& runtime, HttpServeTuning tuning,
             HttpDispatchMode mode = HttpDispatchMode::client_server)
        : m_pool{pool_size}
    {
        REQUIRE(m_acceptor.bind("127.0.0.1", 0U).ok);
        m_port = m_acceptor.bound_port();
        REQUIRE(m_port > 0U);
        m_thread = std::thread{[this, &runtime, tuning, mode]() {
            merovingian::homeserver::serve_http(m_acceptor, runtime, m_shutdown, m_stats, mode, m_pool, nullptr,
                                                tuning);
        }};
    }
    Listener(Listener const&) = delete;
    auto operator=(Listener const&) -> Listener& = delete;
    Listener(Listener&&) = delete;
    auto operator=(Listener&&) -> Listener& = delete;
    ~Listener()
    {
        stop();
    }

    [[nodiscard]] auto port() const noexcept -> std::uint16_t
    {
        return m_port;
    }

    // Returns how long stopping took: the listener, parked connections, and
    // every worker.
    auto stop() -> std::chrono::milliseconds
    {
        auto const started = std::chrono::steady_clock::now();
        m_shutdown.fire();
        if (m_thread.joinable())
        {
            m_thread.join();
        }
        m_pool.request_stop();
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
    }

private:
    merovingian::net::TcpAcceptor m_acceptor{};
    merovingian::net::ShutdownSignal m_shutdown{};
    merovingian::homeserver::HttpServeStats m_stats{};
    merovingian::net::ThreadPool m_pool;
    std::uint16_t m_port{0U};
    std::thread m_thread{};
};

[[nodiscard]] auto other_client_available() -> bool
{
    auto socket = ClientSocket{::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)};
    auto local = sockaddr_in{};
    local.sin_family = AF_INET;
    std::ignore = ::inet_pton(AF_INET, "127.0.0.2", &local.sin_addr);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    return ::bind(socket.fd(), reinterpret_cast<sockaddr const*>(&local), sizeof(local)) == 0;
}

[[nodiscard]] auto access_token_for(merovingian::homeserver::ClientServerRuntime& runtime,
                                    std::string_view localpart) -> std::string
{
    auto const registration = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST",
                  "/_matrix/client/v3/register",
                  {},
                  merovingian::tests::registration_json(localpart, "CorrectHorse7!")});
    REQUIRE(registration.response.status == 200U);
    auto const parsed = merovingian::canonicaljson::parse_lossless(registration.response.body);
    REQUIRE(parsed.error == merovingian::canonicaljson::ParseError::none);
    auto const* object = std::get_if<merovingian::canonicaljson::Object>(&parsed.value.storage());
    REQUIRE(object != nullptr);
    for (auto const& member : *object)
    {
        if (member.key == "access_token")
        {
            return *std::get_if<std::string>(&member.value->storage());
        }
    }
    FAIL("registration returned no access_token");
    return {};
}

} // namespace

SCENARIO("One client keeping every connection alive does not hold the workers another client needs",
         "[http-1][homeserver][http][integration][security]")
{
    GIVEN("a pool of four workers and a two-second keep-alive idle window")
    {
        if (!other_client_available())
        {
            SKIP("127.0.0.2 is not a local address on this host");
        }
        auto config = base_config();
        config.server().http.keep_alive_idle_seconds = 2U;
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);
        auto runtime = std::move(runtime_result.runtime);
        auto listener = Listener{runtime, HttpServeTuning{}};

        WHEN("one client holds four keep-alive connections, sending a request on each every idle - 1 seconds")
        {
            auto held = std::vector<ClientSocket>{};
            auto first_round_ok = true;
            for (auto index = std::size_t{0U}; index < pool_size; ++index)
            {
                held.push_back(connect_main(listener.port()));
                first_round_ok = first_round_ok && send_all(held.back().fd(), versions_request);
                auto const response = receive_response(held.back().fd());
                first_round_ok = first_round_ok && response.find("Connection: keep-alive") != std::string::npos;
            }
            auto holder_ok = std::atomic<bool>{true};
            auto holder = std::thread{[&]() {
                for (auto round = 0; round < 3; ++round)
                {
                    std::this_thread::sleep_for(1000ms);
                    for (auto const& socket : held)
                    {
                        if (!send_all(socket.fd(), versions_request) ||
                            !receive_response(socket.fd()).starts_with("HTTP/1.1 200"))
                        {
                            holder_ok.store(false);
                        }
                    }
                }
            }};
            std::this_thread::sleep_for(300ms);
            auto const other = timed_request_from("127.0.0.2", listener.port());
            holder.join();

            THEN("a request from a different client completes within one second, and the holder is still served")
            {
                REQUIRE(first_round_ok);
                REQUIRE(other.status == SourceConnect::connected);
                INFO("other client's response: " << other.response);
                REQUIRE(other.response.starts_with("HTTP/1.1 200"));
                REQUIRE(other.elapsed < 1000ms);
                REQUIRE(holder_ok.load());
            }
        }
    }
}

SCENARIO("One client trickling request bodies does not hold the workers another client needs, and is cut off",
         "[http-1][homeserver][http][integration][security]")
{
    GIVEN("a pool of four workers and a minimum body rate of 1 KiB/s after a one-second grace")
    {
        if (!other_client_available())
        {
            SKIP("127.0.0.2 is not a local address on this host");
        }
        auto const config = base_config();
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);
        auto runtime = std::move(runtime_result.runtime);
        auto tuning = HttpServeTuning{};
        tuning.body_rate_grace = 1000ms;
        tuning.body_min_bytes_per_second = 1024U;
        auto listener = Listener{runtime, tuning};

        WHEN("one client opens four connections and trickles a declared 4 KiB body on each, one byte every 500 ms")
        {
            auto trickling = std::vector<ClientSocket>{};
            for (auto index = std::size_t{0U}; index < pool_size; ++index)
            {
                trickling.push_back(connect_main(listener.port()));
                REQUIRE(send_all(trickling.back().fd(),
                                 "POST /_matrix/client/v3/register HTTP/1.1\r\nHost: localhost\r\n"
                                 "Content-Type: application/json\r\nContent-Length: 4096\r\n\r\n{"));
            }
            auto collected = std::vector<std::string>(pool_size);
            auto closed = std::vector<bool>(pool_size, false);
            auto trickler = std::thread{[&]() {
                auto const give_up = std::chrono::steady_clock::now() + 20s;
                while (std::chrono::steady_clock::now() < give_up)
                {
                    auto all_closed = true;
                    for (auto index = std::size_t{0U}; index < pool_size; ++index)
                    {
                        if (closed[index])
                        {
                            continue;
                        }
                        if (closed_now(trickling[index].fd(), collected[index]))
                        {
                            closed[index] = true;
                            continue;
                        }
                        if (!send_all(trickling[index].fd(), "x"))
                        {
                            // The server hung up between the check and the
                            // write; collect whatever it answered first.
                            std::ignore = closed_now(trickling[index].fd(), collected[index]);
                            closed[index] = true;
                            continue;
                        }
                        all_closed = false;
                    }
                    if (all_closed)
                    {
                        return;
                    }
                    std::this_thread::sleep_for(500ms);
                }
            }};
            std::this_thread::sleep_for(300ms);
            auto const other = timed_request_from("127.0.0.2", listener.port());
            trickler.join();

            THEN("a request from a different client completes within one second")
            {
                REQUIRE(other.status == SourceConnect::connected);
                INFO("other client's response: " << other.response);
                REQUIRE(other.response.starts_with("HTTP/1.1 200"));
                REQUIRE(other.elapsed < 1000ms);
            }

            THEN("every trickling connection is answered 408 and closed once the rate rule trips")
            {
                for (auto index = std::size_t{0U}; index < pool_size; ++index)
                {
                    INFO("connection " << index << " received: " << collected[index]);
                    REQUIRE(closed[index]);
                    REQUIRE(collected[index].starts_with("HTTP/1.1 408"));
                }
            }
        }
    }
}

SCENARIO("Connections that never send a byte do not hold the workers another client needs",
         "[http-1][homeserver][http][integration][security]")
{
    GIVEN("a pool of four workers and a one-second first-byte timeout")
    {
        if (!other_client_available())
        {
            SKIP("127.0.0.2 is not a local address on this host");
        }
        auto const config = base_config();
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);
        auto runtime = std::move(runtime_result.runtime);
        auto tuning = HttpServeTuning{};
        tuning.first_byte_timeout = 1000ms;
        auto listener = Listener{runtime, tuning};

        WHEN("one client opens eight connections and sends nothing on them")
        {
            auto idle = std::vector<ClientSocket>{};
            for (auto index = 0; index < 8; ++index)
            {
                idle.push_back(connect_main(listener.port()));
            }
            std::this_thread::sleep_for(200ms);
            auto const other = timed_request_from("127.0.0.2", listener.port());
            auto all_closed = true;
            for (auto const& socket : idle)
            {
                auto collected = std::string{};
                all_closed = all_closed && closed_within(socket.fd(), 5000ms, collected);
            }

            THEN("another client is served within one second, and the idle connections are closed")
            {
                REQUIRE(other.status == SourceConnect::connected);
                INFO("other client's response: " << other.response);
                REQUIRE(other.response.starts_with("HTTP/1.1 200"));
                REQUIRE(other.elapsed < 1000ms);
                REQUIRE(all_closed);
            }
        }
    }
}

SCENARIO("An unauthenticated media upload declaring the maximum size is refused before its body is read",
         "[http-1][http-6][homeserver][http][media][integration][security]")
{
    GIVEN("a client listener with the default 50 MiB upload limit")
    {
        auto const config = base_config();
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);
        auto runtime = std::move(runtime_result.runtime);
        auto const token = access_token_for(runtime, "uploader");
        auto listener = Listener{runtime, HttpServeTuning{}};
        auto const max_upload = std::string{"52428800"};

        WHEN("a client with no access token declares a 50 MiB upload and sends none of the body")
        {
            auto socket = connect_main(listener.port());
            auto const started = std::chrono::steady_clock::now();
            REQUIRE(send_all(socket.fd(), "POST /_matrix/media/v3/upload?filename=a.bin HTTP/1.1\r\nHost: localhost\r\n"
                                          "Content-Type: application/octet-stream\r\nContent-Length: " +
                                              max_upload + "\r\n\r\n"));
            auto collected = std::string{};
            auto const closed = closed_within(socket.fd(), 4000ms, collected);
            auto const elapsed = std::chrono::steady_clock::now() - started;

            THEN("it is answered 401 M_MISSING_TOKEN at once and the connection is closed")
            {
                INFO("received: " << collected);
                REQUIRE(collected.starts_with("HTTP/1.1 401"));
                REQUIRE(collected.find("M_MISSING_TOKEN") != std::string::npos);
                REQUIRE(closed);
                REQUIRE(elapsed < 2000ms);
            }
        }

        WHEN("a client with an unknown access token does the same on the authenticated upload route")
        {
            auto socket = connect_main(listener.port());
            REQUIRE(send_all(socket.fd(), "POST /_matrix/client/v1/media/upload HTTP/1.1\r\nHost: localhost\r\n"
                                          "Authorization: Bearer not-a-real-token\r\n"
                                          "Content-Type: application/octet-stream\r\nContent-Length: " +
                                              max_upload + "\r\n\r\n"));
            auto collected = std::string{};
            auto const closed = closed_within(socket.fd(), 4000ms, collected);

            THEN("it is answered 401 M_UNKNOWN_TOKEN and the connection is closed")
            {
                INFO("received: " << collected);
                REQUIRE(collected.starts_with("HTTP/1.1 401"));
                REQUIRE(collected.find("M_UNKNOWN_TOKEN") != std::string::npos);
                REQUIRE(closed);
            }
        }

        WHEN("a client with a valid access token uploads a body larger than the general 1 MiB body cap")
        {
            auto socket = connect_main(listener.port());
            auto const body = std::string(2U * 1024U * 1024U, 'z');
            REQUIRE(send_all(socket.fd(), "POST /_matrix/media/v3/upload?filename=b.bin HTTP/1.1\r\nHost: localhost\r\n"
                                          "Authorization: Bearer " +
                                              token + "\r\nContent-Type: application/octet-stream\r\nContent-Length: " +
                                              std::to_string(body.size()) + "\r\n\r\n"));
            REQUIRE(send_all(socket.fd(), body));
            auto const response = receive_response(socket.fd(), 20000ms);

            THEN("the body is read under the raised upload cap and the upload succeeds")
            {
                INFO("received: " << response.substr(0U, 512U));
                REQUIRE(response.starts_with("HTTP/1.1 200"));
                REQUIRE(response.find("content_uri") != std::string::npos);
            }
        }
    }
}

SCENARIO("A kept-alive connection is closed after the per-connection request cap",
         "[http-8][homeserver][http][integration][security]")
{
    GIVEN("a listener that allows three requests per connection")
    {
        auto const config = base_config();
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);
        auto runtime = std::move(runtime_result.runtime);
        auto tuning = HttpServeTuning{};
        tuning.max_requests_per_connection = 3U;
        auto listener = Listener{runtime, tuning};

        WHEN("a client sends three requests on one connection")
        {
            auto socket = connect_main(listener.port());
            auto responses = std::vector<std::string>{};
            for (auto index = 0; index < 3; ++index)
            {
                REQUIRE(send_all(socket.fd(), versions_request));
                responses.push_back(receive_response(socket.fd()));
            }
            auto collected = std::string{};
            auto const closed = closed_within(socket.fd(), 3000ms, collected);

            THEN("the first two are kept alive, the third says Connection: close, and the server closes")
            {
                REQUIRE(responses[0].find("Connection: keep-alive") != std::string::npos);
                REQUIRE(responses[1].find("Connection: keep-alive") != std::string::npos);
                INFO("third response: " << responses[2]);
                REQUIRE(responses[2].starts_with("HTTP/1.1 200"));
                REQUIRE(responses[2].find("Connection: close") != std::string::npos);
                REQUIRE(closed);
            }
        }
    }
}

SCENARIO("A kept-alive connection is closed after the per-connection lifetime cap",
         "[http-8][homeserver][http][integration][security]")
{
    GIVEN("a listener that allows a connection one second of life")
    {
        auto const config = base_config();
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);
        auto runtime = std::move(runtime_result.runtime);
        auto tuning = HttpServeTuning{};
        tuning.max_connection_lifetime = std::chrono::seconds{1};
        auto listener = Listener{runtime, tuning};

        WHEN("a client sends a request, waits past the lifetime, and sends another")
        {
            auto socket = connect_main(listener.port());
            REQUIRE(send_all(socket.fd(), versions_request));
            auto const first = receive_response(socket.fd());
            std::this_thread::sleep_for(1200ms);
            REQUIRE(send_all(socket.fd(), versions_request));
            auto const second = receive_response(socket.fd());
            auto collected = std::string{};
            auto const closed = closed_within(socket.fd(), 3000ms, collected);

            THEN("the first response keeps the connection and the second closes it")
            {
                REQUIRE(first.find("Connection: keep-alive") != std::string::npos);
                INFO("second response: " << second);
                REQUIRE(second.starts_with("HTTP/1.1 200"));
                REQUIRE(second.find("Connection: close") != std::string::npos);
                REQUIRE(closed);
            }
        }
    }
}

SCENARIO("One client's stalled request holds only its own share of the workers; a trusted proxy is exempt",
         "[http-1][homeserver][http][integration][security]")
{
    GIVEN("a pool of four workers (one per client) and a three-second body grace")
    {
        auto tuning = HttpServeTuning{};
        tuning.body_rate_grace = 3000ms;
        tuning.body_min_bytes_per_second = 1024U;
        auto const stalled_head = std::string_view{"POST /_matrix/client/v3/register HTTP/1.1\r\nHost: localhost\r\n"
                                                   "Content-Type: application/json\r\nContent-Length: 100\r\n\r\n{"};

        WHEN("an ordinary client stalls in a request body and then sends a second request on another connection")
        {
            auto const config = base_config();
            auto runtime_result = merovingian::homeserver::start_client_server(config);
            REQUIRE(runtime_result.started);
            auto runtime = std::move(runtime_result.runtime);
            auto listener = Listener{runtime, tuning};

            auto stalled = connect_main(listener.port());
            REQUIRE(send_all(stalled.fd(), stalled_head));
            std::this_thread::sleep_for(300ms);
            auto const started = std::chrono::steady_clock::now();
            auto second = connect_main(listener.port());
            REQUIRE(send_all(second.fd(), versions_request));
            auto const second_response = receive_response(second.fd(), 10000ms);
            auto const second_elapsed = std::chrono::steady_clock::now() - started;
            auto stalled_collected = std::string{};
            auto const stalled_closed = closed_within(stalled.fd(), 5000ms, stalled_collected);

            THEN("the second request waits until the stalled one is cut off")
            {
                INFO("second response: " << second_response);
                REQUIRE(second_response.starts_with("HTTP/1.1 200"));
                REQUIRE(second_elapsed >= 2000ms);
                REQUIRE(stalled_closed);
                REQUIRE(stalled_collected.starts_with("HTTP/1.1 408"));
            }
        }

        WHEN("the same happens through an address configured as a trusted proxy")
        {
            auto config = base_config();
            config.server().trusted_proxies = {"127.0.0.1"};
            auto runtime_result = merovingian::homeserver::start_client_server(config);
            REQUIRE(runtime_result.started);
            auto runtime = std::move(runtime_result.runtime);
            auto listener = Listener{runtime, tuning};

            auto stalled = connect_main(listener.port());
            REQUIRE(send_all(stalled.fd(), stalled_head));
            std::this_thread::sleep_for(300ms);
            auto const started = std::chrono::steady_clock::now();
            auto second = connect_main(listener.port());
            REQUIRE(send_all(second.fd(), versions_request));
            auto const second_response = receive_response(second.fd(), 10000ms);
            auto const second_elapsed = std::chrono::steady_clock::now() - started;

            THEN("the second request is served at once: the proxy is responsible for per-client fairness")
            {
                INFO("second response: " << second_response);
                REQUIRE(second_response.starts_with("HTTP/1.1 200"));
                REQUIRE(second_elapsed < 1000ms);
            }
        }
    }
}

SCENARIO("Shutdown with parked connections completes promptly", "[http-1][homeserver][http][integration]")
{
    GIVEN("a pool of four workers")
    {
        auto const config = base_config();
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);
        auto runtime = std::move(runtime_result.runtime);
        auto listener = Listener{runtime, HttpServeTuning{}};

        WHEN("six connections have sent nothing and two are parked between keep-alive requests, and the server stops")
        {
            auto sockets = std::vector<ClientSocket>{};
            for (auto index = 0; index < 6; ++index)
            {
                sockets.push_back(connect_main(listener.port()));
            }
            for (auto index = 0; index < 2; ++index)
            {
                sockets.push_back(connect_main(listener.port()));
                REQUIRE(send_all(sockets.back().fd(), versions_request));
                REQUIRE(receive_response(sockets.back().fd()).find("Connection: keep-alive") != std::string::npos);
            }
            std::this_thread::sleep_for(300ms);
            auto const stop_elapsed = listener.stop();
            auto all_closed = true;
            for (auto const& socket : sockets)
            {
                auto collected = std::string{};
                all_closed = all_closed && closed_within(socket.fd(), 1000ms, collected);
            }

            THEN("the listener, the parked connections and the workers all stop within two seconds")
            {
                REQUIRE(stop_elapsed < 2000ms);
                REQUIRE(all_closed);
            }
        }
    }
}
