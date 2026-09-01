// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// +-------------------------------------------------------------------------+
// |        APPLICATION SERVICE USER / ROOM-ALIAS QUERY HOOKS                 |
// |                                                                         |
// |  Spec: Matrix Application Service API v1.19, "User IDs" and             |
// |        "Room Aliases".                                                  |
// |  URL:  ../../docs/matrix-v1.19-spec/application-service-api.md          |
// |                                                                         |
// |  When an identifier inside an appservice's namespace is unknown         |
// |  locally, the homeserver asks that appservice before answering 404 —    |
// |  a bridge materialises users and rooms on demand, so a flat 404 makes   |
// |  the namespace pointless. These drive a real local mock appservice and  |
// |  assert on the bytes the homeserver actually put on the wire, because   |
// |  the outbound half existed as dead code before and still compiled.      |
// +-------------------------------------------------------------------------+

#include "../support/registration_token.hpp"
#include "../support/tls_mock_server.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/net/tcp_acceptor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <thread>
#include <vector>

#include <unistd.h>

namespace
{

using namespace merovingian::tests;

// One-shot plain-HTTP mock appservice: accepts a single connection, reads the
// request headers, replies, and closes. `captured_request` stays empty when no
// connection ever arrives, which is how the "must not be queried" cases assert
// that the homeserver kept quiet.
auto run_one_shot_appservice_server(merovingian::net::TcpAcceptor& acceptor, std::string const& http_response,
                                    std::string* captured_request) noexcept -> void
{
    auto const client_fd = tls_mock::accept_loopback(acceptor, 2000);
    if (client_fd < 0)
    {
        return;
    }
    auto buffer = std::array<char, 8192>{};
    auto request_bytes = std::string{};
    while (request_bytes.find("\r\n\r\n") == std::string::npos)
    {
        auto const bytes_read = ::read(client_fd, buffer.data(), buffer.size());
        if (bytes_read <= 0)
        {
            break;
        }
        request_bytes.append(buffer.data(), static_cast<std::size_t>(bytes_read));
        if (static_cast<std::size_t>(bytes_read) < buffer.size())
        {
            break;
        }
    }
    if (captured_request != nullptr)
    {
        *captured_request = request_bytes;
    }
    static_cast<void>(::write(client_fd, http_response.data(), http_response.size()));
    ::close(client_fd);
}

// A registration claiming `@_bridge_.*` users and `#_bridge_.*` aliases.
[[nodiscard]] auto config_with_namespaced_appservice(std::filesystem::path const& registration_path,
                                                     std::uint16_t mock_port) -> merovingian::config::Config
{
    {
        auto out = std::ofstream{registration_path, std::ios::binary};
        out << R"({
            "id": "bridge",
            "url": "http://127.0.0.1:)"
            << mock_port << R"(",
            "as_token": "as-token-value",
            "hs_token": "hs-token-value",
            "sender_localpart": "_bridge_bot",
            "namespaces": {
                "users": [{"exclusive": true, "regex": "@_bridge_.*"}],
                "aliases": [{"exclusive": true, "regex": "#_bridge_.*"}],
                "rooms": []
            },
            "protocols": []
        })";
    }
    auto security = merovingian::config::SecurityConfig{};
    enable_token_registration(security);
    auto config = merovingian::config::Config{
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
    };
    config.appservice().registration_files = {registration_path.string()};
    return config;
}

[[nodiscard]] auto register_and_login(merovingian::homeserver::ClientServerRuntime& runtime,
                                      std::string const& localpart) -> std::string
{
    auto const reg = merovingian::homeserver::handle_client_server_request(
        runtime, {"POST", "/_matrix/client/v3/register", {}, registration_json(localpart, "CorrectHorse7!")});
    REQUIRE(reg.response.status == 200U);
    auto const token_key = std::string{"\"access_token\":\""};
    auto const start = reg.response.body.find(token_key);
    REQUIRE(start != std::string::npos);
    auto const value_start = start + token_key.size();
    auto const value_end = reg.response.body.find('"', value_start);
    REQUIRE(value_end != std::string::npos);
    return reg.response.body.substr(value_start, value_end - value_start);
}

} // namespace

SCENARIO("an unknown room alias inside an appservice namespace is queried before 404",
         "[appservice][integration][queryhooks]")
{
    GIVEN("an appservice claiming #_bridge_.* and a mock server that declines the alias")
    {
        auto const path = std::filesystem::temp_directory_path() / "merovingian-queryhook-alias.json";
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto started = merovingian::homeserver::start_client_server(config_with_namespaced_appservice(path, port));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login(runtime, "alice");

        auto captured = std::string{};
        auto server_thread = std::thread{[&] {
            run_one_shot_appservice_server(acceptor, tls_mock::json_http_response("404 Not Found", "{}"), &captured);
        }};
        auto const join = tls_mock::ScopedThreadJoin{server_thread};

        WHEN("a client resolves an alias in that namespace that the homeserver does not know")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/directory/room/%23_bridge_chan%3Aexample.org", token, {}});
            if (server_thread.joinable())
            {
                server_thread.join();
            }

            THEN("the homeserver asked the owning appservice for it")
            {
                REQUIRE(captured.find("/_matrix/app/v1/rooms/") != std::string::npos);
            }

            THEN("the query carried the appservice's hs_token")
            {
                // The hs_token authenticates the homeserver TO the appservice;
                // a bridge must be able to tell a real homeserver call from an
                // attacker's, so its absence would be a security defect, not a
                // cosmetic one.
                REQUIRE(captured.find("hs-token-value") != std::string::npos);
            }

            THEN("a declining appservice still yields 404, not a transport error")
            {
                REQUIRE(response.response.status == 404U);
            }
        }
    }
}

SCENARIO("an unknown alias outside every appservice namespace is not sent to any appservice",
         "[appservice][integration][queryhooks][security]")
{
    GIVEN("the same appservice, claiming only #_bridge_.*")
    {
        auto const path = std::filesystem::temp_directory_path() / "merovingian-queryhook-alias-outside.json";
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto started = merovingian::homeserver::start_client_server(config_with_namespaced_appservice(path, port));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login(runtime, "alice");

        auto captured = std::string{};
        auto server_thread = std::thread{[&] {
            run_one_shot_appservice_server(acceptor, tls_mock::json_http_response("200 OK", "{}"), &captured);
        }};
        auto const join = tls_mock::ScopedThreadJoin{server_thread};

        WHEN("a client resolves an unrelated unknown alias")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/directory/room/%23nobody%3Aexample.org", token, {}});
            if (server_thread.joinable())
            {
                server_thread.join();
            }

            THEN("no appservice was contacted")
            {
                // Querying outside an appservice's namespace would tell a
                // bridge which aliases unrelated clients are looking up.
                REQUIRE(captured.empty());
            }

            THEN("the client still gets 404")
            {
                REQUIRE(response.response.status == 404U);
            }
        }
    }
}

SCENARIO("an unknown user inside an appservice namespace is queried before 404",
         "[appservice][integration][queryhooks]")
{
    GIVEN("an appservice claiming @_bridge_.* and a mock server that declines the user")
    {
        auto const path = std::filesystem::temp_directory_path() / "merovingian-queryhook-user.json";
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto started = merovingian::homeserver::start_client_server(config_with_namespaced_appservice(path, port));
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const token = register_and_login(runtime, "alice");

        auto captured = std::string{};
        auto server_thread = std::thread{[&] {
            run_one_shot_appservice_server(acceptor, tls_mock::json_http_response("404 Not Found", "{}"), &captured);
        }};
        auto const join = tls_mock::ScopedThreadJoin{server_thread};

        WHEN("a client fetches the profile of an unknown user in that namespace")
        {
            auto const response = merovingian::homeserver::handle_client_server_request(
                runtime, {"GET", "/_matrix/client/v3/profile/%40_bridge_alice%3Aexample.org", token, {}});
            if (server_thread.joinable())
            {
                server_thread.join();
            }

            THEN("the homeserver asked the owning appservice for it")
            {
                REQUIRE(captured.find("/_matrix/app/v1/users/") != std::string::npos);
            }

            THEN("a declining appservice still yields 404")
            {
                REQUIRE(response.response.status == 404U);
            }
        }
    }
}
