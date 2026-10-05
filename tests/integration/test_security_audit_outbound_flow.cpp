// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/tls_mock_server.hpp"
#include "merovingian/core/socket_handle.hpp"
#include "merovingian/http/outbound_client.hpp"
#include "merovingian/net/tcp_acceptor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <cctype>
#include <string>
#include <thread>

#include <poll.h>
#include <sys/socket.h>

namespace
{

[[nodiscard]] auto lowercase_ascii(std::string text) -> std::string
{
    std::ranges::transform(text, text.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return text;
}

[[nodiscard]] auto accepted_connection_count(merovingian::net::TcpAcceptor& acceptor) -> int
{
    auto poll_entry = pollfd{acceptor.fd(), POLLIN, 0};
    auto const ready = ::poll(&poll_entry, 1U, 100);
    if (ready <= 0)
    {
        return 0;
    }

    auto const accepted_fd = ::accept(acceptor.fd(), nullptr, nullptr);
    if (accepted_fd < 0)
    {
        return 0;
    }
    auto const accepted_socket = merovingian::core::SocketHandle{accepted_fd};
    return accepted_socket.valid() ? 1 : 0;
}

SCENARIO("OutboundClient retains every approved address and supports IPv6 socket pins",
         "[http][outbound][security][integration][security_audit_outbound]")
{
    GIVEN("a trusted HTTPS peer and a pinned request")
    {
        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
        auto tls = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                    certificate.private_key_file);
        REQUIRE(tls.ok());
        auto acceptor = merovingian::net::TcpAcceptor{};
        auto request = merovingian::http::OutboundRequest{};
        request.trusted_ca_pem = certificate.certificate_pem;
        request.connect_timeout_seconds = 1U;
        request.total_timeout_seconds = 2U;
        WHEN("the live IPv4 address precedes an unreachable address in the approved set")
        {
            REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
            request.pinned_addresses = {"127.0.0.1", "127.0.0.2"};
            THEN("the live pin remains available rather than being overwritten by the last entry")
            {
                request.url = "https://localhost:" + std::to_string(acceptor.bound_port()) + "/%2e%2e/item?x=1";
                auto captured = std::string{};
                auto thread = std::thread{[&]() {
                    merovingian::tests::tls_mock::run_one_shot_tls_server(
                        acceptor, *tls.context, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        &captured);
                }};
                auto const joined = merovingian::tests::tls_mock::ScopedThreadJoin{thread};
                auto client = merovingian::http::OutboundClient{};
                auto const result = client.perform(request);
                thread.join();
                REQUIRE(result.ok);
                REQUIRE(result.response.body == "ok");
                // The encoded dot segment must reach the peer rather than be
                // resolved away. libcurl 8.20 and later upper-case
                // percent-encoding hex digits (equivalent under RFC 3986
                // §6.2.2.1), so compare the request line case-insensitively.
                auto const request_line = lowercase_ascii(captured.substr(0U, captured.find("\r\n")));
                REQUIRE(request_line.starts_with("get /%2e%2e/item?x=1 http/"));
            }
        }
        WHEN("the approved peer is an IPv6 address")
        {
            REQUIRE(acceptor.bind("::1", 0U).ok);
            request.pinned_addresses = {"::1"};
            THEN("the actual IPv6 peer passes the binary address and port check")
            {
                request.url = "https://localhost:" + std::to_string(acceptor.bound_port()) + "/item";
                auto thread = std::thread{[&]() {
                    merovingian::tests::tls_mock::run_one_shot_tls_server(
                        acceptor, *tls.context, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok");
                }};
                auto const joined = merovingian::tests::tls_mock::ScopedThreadJoin{thread};
                auto client = merovingian::http::OutboundClient{};
                auto const result = client.perform(request);
                thread.join();
                REQUIRE(result.ok);
                REQUIRE(result.response.body == "ok");
            }
        }
    }
}

} // namespace

SCENARIO("OutboundClient rejects credentialed URL authority before opening a socket",
         "[http][outbound][security][integration][security_audit_outbound]")
{
    GIVEN("a loopback listener and a credentialed HTTPS URL whose actual host is that listener")
    {
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);

        auto request = merovingian::http::OutboundRequest{};
        request.url = "https://user@127.0.0.1:" + std::to_string(acceptor.bound_port()) + "/path";
        request.pinned_addresses = {"203.0.113.10"};
        request.connect_timeout_seconds = 1U;
        request.total_timeout_seconds = 1U;

        WHEN("perform is invoked")
        {
            auto client = merovingian::http::OutboundClient{};
            auto const result = client.perform(request);

            THEN("the URL is rejected and no TCP connection reaches the listener")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.error == merovingian::http::OutboundError::invalid_url);
                REQUIRE(accepted_connection_count(acceptor) == 0);
            }
        }
    }
}

SCENARIO("OutboundClient refuses a numeric peer that is absent from the approved pin set",
         "[http][outbound][security][integration][security_audit_outbound]")
{
    GIVEN("a loopback listener but only a public address in the request's approved pin set")
    {
        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);

        auto request = merovingian::http::OutboundRequest{};
        request.url = "https://127.0.0.1:" + std::to_string(acceptor.bound_port()) + "/path";
        request.pinned_addresses = {"203.0.113.10"};
        request.connect_timeout_seconds = 1U;
        request.total_timeout_seconds = 1U;

        WHEN("perform opens the outbound connection")
        {
            auto client = merovingian::http::OutboundClient{};
            auto const result = client.perform(request);

            THEN("the actual loopback peer is rejected before any socket reaches the listener")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(accepted_connection_count(acceptor) == 0);
            }
        }
    }
}
