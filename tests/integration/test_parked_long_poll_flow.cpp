// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
//
// ADR-0569 (finding P15a): a /sync long-poll with nothing to return parks in the notifier's registry and gives up its
// sync-pool thread. Every scenario runs a real listener on loopback with a sync pool of TWO threads, so more
// concurrent long-polls than sync threads can only complete if the waiting ones hold no thread.
//
// Tags: [p15a] [sync] [homeserver] [http] [integration].

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "bounded_connect.hpp"
#include "merovingian/config/ClientRateLimitsConfig.hpp"
#include "merovingian/config/Config.hpp"
#include "merovingian/config/ListenersConfig.hpp"
#include "merovingian/config/LogModulesConfig.hpp"
#include "merovingian/config/SecurityConfig.hpp"
#include "merovingian/config/ServerConfig.hpp"
#include "merovingian/homeserver/ClientServerRuntime.hpp"
#include "merovingian/homeserver/ClientServerStartResult.hpp"
#include "merovingian/homeserver/HttpServeStats.hpp"
#include "merovingian/homeserver/HttpServeTuning.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/http_server.hpp"
#include "merovingian/net/ShutdownSignal.hpp"
#include "merovingian/net/TcpAcceptor.hpp"
#include "merovingian/net/ThreadPool.hpp"
#include "merovingian/sync/SyncNotifier.hpp"

#include <arpa/inet.h>
#include <catch2/catch_test_macros.hpp>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace
{

using namespace std::chrono_literals;
using merovingian::homeserver::ClientServerRuntime;

constexpr auto request_pool_size = std::size_t{4U};
constexpr auto sync_pool_size = std::size_t{2U};
constexpr auto poller_count = std::size_t{12U};

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

// A client socket, closed on scope exit.
class Client final
{
public:
    explicit Client(int fd) noexcept
        : m_fd{fd}
    {
    }
    Client(Client const&) = delete;
    auto operator=(Client const&) -> Client& = delete;
    Client(Client&& other) noexcept
        : m_fd{std::exchange(other.m_fd, -1)}
    {
    }
    auto operator=(Client&&) -> Client& = delete;
    ~Client()
    {
        if (m_fd >= 0)
        {
            ::close(m_fd);
        }
    }
    [[nodiscard]] auto fd() const noexcept -> int
    {
        return m_fd;
    }

private:
    int m_fd;
};

[[nodiscard]] auto connect_to(std::uint16_t port) -> Client
{
    auto client = Client{::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)};
    auto remote = sockaddr_in{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(port);
    remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    REQUIRE(
        merovingian::tests::connect_within(client.fd(), *reinterpret_cast<sockaddr const*>(&remote), sizeof(remote)));
    return client;
}

[[nodiscard]] auto send_all(int fd, std::string_view data) -> bool
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

// Reads until the peer closes or `within` passes; a response carrying `Connection: close` ends with the close.
[[nodiscard]] auto read_until_close(int fd, std::chrono::milliseconds within) -> std::string
{
    auto const deadline = std::chrono::steady_clock::now() + within;
    auto collected = std::string{};
    auto buffer = std::array<char, 4096U>{};
    while (true)
    {
        auto const remaining =
            std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        if (remaining.count() <= 0)
        {
            return collected;
        }
        auto entry = pollfd{};
        entry.fd = fd;
        entry.events = POLLIN;
        if (::poll(&entry, 1U, static_cast<int>(remaining.count())) <= 0)
        {
            return collected;
        }
        auto const received = ::recv(fd, buffer.data(), buffer.size(), 0);
        if (received <= 0)
        {
            return collected;
        }
        collected.append(buffer.data(), static_cast<std::size_t>(received));
    }
}

[[nodiscard]] auto json_string_after(std::string const& body, std::string_view key) -> std::string
{
    auto const needle = "\"" + std::string{key} + "\":\"";
    auto const start = body.find(needle);
    if (start == std::string::npos)
    {
        return {};
    }
    auto const value_start = start + needle.size();
    return body.substr(value_start, body.find('"', value_start) - value_start);
}

[[nodiscard]] auto percent_encode_room(std::string const& room_id) -> std::string
{
    auto encoded = std::string{};
    for (auto const ch : room_id)
    {
        if (ch == '!')
        {
            encoded += "%21";
        }
        else if (ch == ':')
        {
            encoded += "%3A";
        }
        else
        {
            encoded += ch;
        }
    }
    return encoded;
}

// A listener with a small sync pool, served until destruction.
class Listener final
{
public:
    explicit Listener(ClientServerRuntime& runtime)
        : m_pool{request_pool_size}
        , m_sync_pool{sync_pool_size}
    {
        REQUIRE(m_acceptor.bind("127.0.0.1", 0U).ok);
        m_port = m_acceptor.bound_port();
        m_thread = std::thread{[this, &runtime]() {
            merovingian::homeserver::serve_http(m_acceptor, runtime, m_shutdown, m_stats,
                                                merovingian::homeserver::HttpDispatchMode::client_server, m_pool,
                                                &m_sync_pool, merovingian::homeserver::HttpServeTuning{});
        }};
    }
    Listener(Listener const&) = delete;
    auto operator=(Listener const&) -> Listener& = delete;
    Listener(Listener&&) = delete;
    auto operator=(Listener&&) -> Listener& = delete;
    ~Listener()
    {
        std::ignore = stop();
    }
    [[nodiscard]] auto port() const noexcept -> std::uint16_t
    {
        return m_port;
    }
    // How long the listener, the parked polls and both pools took to stop.
    auto stop() -> std::chrono::milliseconds
    {
        auto const started = std::chrono::steady_clock::now();
        m_shutdown.fire();
        if (m_thread.joinable())
        {
            m_thread.join();
        }
        m_pool.request_stop();
        m_sync_pool.request_stop();
        return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
    }

private:
    merovingian::net::TcpAcceptor m_acceptor{};
    merovingian::net::ShutdownSignal m_shutdown{};
    merovingian::homeserver::HttpServeStats m_stats{};
    merovingian::net::ThreadPool m_pool;
    merovingian::net::ThreadPool m_sync_pool;
    std::uint16_t m_port{0U};
    std::thread m_thread{};
};

struct Poller final
{
    std::string token{};
    std::string since{};
};

// A room all pollers share, each with an initial sync token taken after joining.
struct SharedRoom final
{
    std::string room_id{};
    std::string owner_token{};
    std::vector<Poller> pollers{};
};

[[nodiscard]] auto build_shared_room(ClientServerRuntime& runtime) -> SharedRoom
{
    auto room = SharedRoom{};
    auto const owner = merovingian::homeserver::register_local_user(runtime.homeserver, "p15a_owner", "CorrectHorse7!",
                                                                    merovingian::tests::registration_token);
    REQUIRE(owner.ok);
    auto const owner_login = merovingian::homeserver::login_local_user_by_id(runtime.homeserver, owner.value, "OWNER");
    REQUIRE(owner_login.ok);
    room.owner_token = owner_login.value;
    auto const created = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/createRoom", room.owner_token, R"({"preset":"public_chat"})"});
    REQUIRE(created.response.status == 200U);
    room.room_id = json_string_after(created.response.body, "room_id");
    REQUIRE_FALSE(room.room_id.empty());
    for (auto index = std::size_t{0U}; index < poller_count; ++index)
    {
        auto const user =
            merovingian::homeserver::register_local_user(runtime.homeserver, "p15a_poller" + std::to_string(index),
                                                         "CorrectHorse7!", merovingian::tests::registration_token);
        REQUIRE(user.ok);
        auto const login = merovingian::homeserver::login_local_user_by_id(runtime.homeserver, user.value, "POLL");
        REQUIRE(login.ok);
        auto const joined = merovingian::homeserver::handle_client_server_request(
            runtime, {"POST", "/_matrix/client/v3/join/" + percent_encode_room(room.room_id), login.value, "{}"});
        REQUIRE(joined.response.status == 200U);
        room.pollers.push_back({login.value, {}});
    }
    // Every join is done before any initial sync, so no later join is an event after a poller's token.
    for (auto& poller : room.pollers)
    {
        auto const initial = merovingian::homeserver::handle_client_server_request(
            runtime, {"GET", "/_matrix/client/v3/sync?timeout=0&set_presence=offline", poller.token, ""});
        REQUIRE(initial.response.status == 200U);
        poller.since = json_string_after(initial.response.body, "next_batch");
        REQUIRE_FALSE(poller.since.empty());
    }
    return room;
}

[[nodiscard]] auto sync_request(Poller const& poller, std::string_view timeout_ms) -> std::string
{
    return "GET /_matrix/client/v3/sync?since=" + poller.since + "&timeout=" + std::string{timeout_ms} +
           "&set_presence=offline HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + poller.token +
           "\r\nConnection: close\r\n\r\n";
}

// True once `count` long-polls are parked in the registry.
[[nodiscard]] auto wait_until_parked(ClientServerRuntime& runtime, std::size_t count, std::chrono::milliseconds within)
    -> bool
{
    auto const deadline = std::chrono::steady_clock::now() + within;
    while (runtime.sync_notifier->parking().parked() < count && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(10ms);
    }
    return runtime.sync_notifier->parking().parked() >= count;
}

} // namespace

SCENARIO("More concurrent long-polls than sync-pool threads all park and one message wakes them all",
         "[p15a][sync][homeserver][http][integration]")
{
    GIVEN("a sync pool of two threads and twelve users sharing a room, each with a long-poll waiting")
    {
        auto const config = base_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const room = build_shared_room(runtime);
        auto listener = Listener{runtime};
        auto clients = std::vector<Client>{};
        for (auto const& poller : room.pollers)
        {
            clients.push_back(connect_to(listener.port()));
            REQUIRE(send_all(clients.back().fd(), sync_request(poller, "60000")));
        }
        auto const all_parked = wait_until_parked(runtime, poller_count, 15s);

        WHEN("the room owner sends one message")
        {
            auto const sent = merovingian::homeserver::handle_client_server_request(
                runtime,
                {"PUT", "/_matrix/client/v3/rooms/" + percent_encode_room(room.room_id) + "/send/m.room.message/p15a1",
                 room.owner_token, R"({"msgtype":"m.text","body":"wake everyone"})"});
            auto responses = std::vector<std::string>{};
            for (auto const& client : clients)
            {
                responses.push_back(read_until_close(client.fd(), 15s));
            }

            THEN("every long-poll was parked without a thread and every one is answered with the message")
            {
                REQUIRE(all_parked);
                REQUIRE(sent.response.status == 200U);
                for (auto const& response : responses)
                {
                    INFO(response.substr(0U, 200U));
                    REQUIRE(response.starts_with("HTTP/1.1 200"));
                    REQUIRE(response.find("wake everyone") != std::string::npos);
                }
                REQUIRE(runtime.sync_notifier->parking().parked() == 0U);
            }
        }
    }
}

SCENARIO("A parked long-poll with no event is answered when its timeout passes",
         "[p15a][sync][homeserver][http][integration]")
{
    GIVEN("a user long-polling for one second with nothing happening")
    {
        auto const config = base_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const room = build_shared_room(runtime);
        auto listener = Listener{runtime};
        auto client = connect_to(listener.port());
        auto const begun = std::chrono::steady_clock::now();
        REQUIRE(send_all(client.fd(), sync_request(room.pollers.front(), "1000")));
        auto const parked = wait_until_parked(runtime, 1U, 10s);
        INFO("early answer: " + (parked ? std::string{} : read_until_close(client.fd(), 200ms)).substr(0U, 1200U));

        WHEN("the timeout passes")
        {
            auto const response = read_until_close(client.fd(), 15s);
            auto const elapsed = std::chrono::steady_clock::now() - begun;

            THEN("it was parked, then answered 200 after about a second, and nothing is left parked")
            {
                REQUIRE(parked);
                INFO(response.substr(0U, 200U));
                REQUIRE(response.starts_with("HTTP/1.1 200"));
                REQUIRE(elapsed >= 900ms);
                REQUIRE(elapsed < 10s);
                REQUIRE(runtime.sync_notifier->parking().parked() == 0U);
            }
        }
    }
}

SCENARIO("Shutdown with parked long-polls ends promptly and closes them", "[p15a][sync][homeserver][http][integration]")
{
    GIVEN("twelve parked long-polls with a sixty second timeout")
    {
        auto const config = base_config();
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const room = build_shared_room(runtime);
        auto listener = Listener{runtime};
        auto clients = std::vector<Client>{};
        for (auto const& poller : room.pollers)
        {
            clients.push_back(connect_to(listener.port()));
            REQUIRE(send_all(clients.back().fd(), sync_request(poller, "60000")));
        }
        auto const all_parked = wait_until_parked(runtime, poller_count, 15s);

        WHEN("the server stops")
        {
            auto const stop_elapsed = listener.stop();
            auto all_closed = true;
            for (auto const& client : clients)
            {
                auto const left_over = read_until_close(client.fd(), 3s);
                all_closed = all_closed && left_over.find("HTTP/1.1 200") == std::string::npos;
                auto peek = std::array<char, 1U>{};
                auto const peeked = ::recv(client.fd(), peek.data(), 1U, MSG_PEEK | MSG_DONTWAIT);
                all_closed = all_closed && peeked == 0;
            }

            THEN("it stops within two seconds, every poll was parked, and every connection is closed")
            {
                REQUIRE(all_parked);
                REQUIRE(stop_elapsed < 2000ms);
                REQUIRE(all_closed);
                REQUIRE(runtime.sync_notifier->parking().parked() == 0U);
            }
        }
    }
}
