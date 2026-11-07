// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/tls_mock_server.hpp"
#include "merovingian/core/SocketHandle.hpp"
#include "merovingian/homeserver/TlsServerContext.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/http/OutboundClient.hpp"
#include "merovingian/http/OutboundError.hpp"
#include "merovingian/http/OutboundRequest.hpp"
#include "merovingian/net/TcpAcceptor.hpp"

#include <catch2/catch_test_macros.hpp>
#include <fcntl.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <thread>
#include <tuple>
#include <utility>

namespace
{

[[nodiscard]] auto accept_loopback(merovingian::net::TcpAcceptor& acceptor, int timeout_ms) -> int
{
    auto pollfd_entry = ::pollfd{acceptor.fd(), POLLIN, 0};
    auto const ready = ::poll(&pollfd_entry, 1U, timeout_ms);
    if (ready <= 0)
    {
        return -1;
    }
    return ::accept(acceptor.fd(), nullptr, nullptr);
}

// One-shot TLS server: waits for a single connection, completes the
// handshake, drains some request bytes, writes the configured response, and
// closes. The server thread joins quickly even when the client aborts
// because both the accept poll and the TLS handshake carry bounded timeouts.
auto run_one_shot_tls_server(merovingian::net::TcpAcceptor& acceptor,
                             merovingian::homeserver::TlsServerContext& tls_context, std::string const& http_response,
                             std::string* captured_request = nullptr) noexcept -> void
{
    auto const client_fd = accept_loopback(acceptor, 5000);
    if (client_fd < 0)
    {
        return;
    }
    // Owns the accepted descriptor: TlsConnection only borrows it, so without
    // this every served connection stayed open for the rest of the run.
    auto const owned_client_fd = merovingian::core::SocketHandle{client_fd};
    auto tls_result = merovingian::homeserver::accept_tls_connection(tls_context, client_fd, 5000);
    if (!tls_result.connection.has_value())
    {
        return;
    }
    auto& tls_connection = *tls_result.connection;
    auto buffer = std::array<char, 8192>{};
    auto request_bytes = std::string{};
    while (request_bytes.find("\r\n\r\n") == std::string::npos)
    {
        auto const bytes_read = tls_connection.read(buffer.data(), buffer.size());
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
        *captured_request = std::move(request_bytes);
    }
    std::ignore = tls_connection.write(http_response);
}

[[nodiscard]] auto json_http_response(std::string const& status_line, std::string const& body,
                                      std::string const& extra_headers = {}) -> std::string
{
    auto response = std::string{"HTTP/1.1 "};
    response += status_line;
    response += "\r\nContent-Length: ";
    response += std::to_string(body.size());
    response += "\r\nContent-Type: application/json\r\nConnection: close\r\n";
    if (!extra_headers.empty())
    {
        response += extra_headers;
    }
    response += "\r\n";
    response += body;
    return response;
}

[[nodiscard]] auto make_localhost_request(std::uint16_t port, std::string const& host_in_url,
                                          std::string const& trusted_ca_pem) -> merovingian::http::OutboundRequest
{
    auto request = merovingian::http::OutboundRequest{};
    request.method = "GET";
    request.url = "https://" + host_in_url + ":" + std::to_string(port) + "/_matrix/key/v2/server";
    request.pinned_addresses = {"127.0.0.1"};
    request.connect_timeout_seconds = 5U;
    request.total_timeout_seconds = 10U;
    request.trusted_ca_pem = trusted_ca_pem;
    return request;
}

} // namespace

SCENARIO("OutboundClient round-trips an HTTPS request through a trusted local TLS server",
         "[http][outbound][tls][integration]")
{
    GIVEN("a one-shot TLS server with a self-signed CN=localhost certificate and a request that trusts it")
    {
        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto const body = std::string{R"({"server_name":"localhost"})"};
        auto const response = json_http_response("200 OK", body);

        WHEN("OutboundClient::perform is invoked with the matching hostname and trusted CA")
        {
            auto server_thread = std::thread{[&]() {
                run_one_shot_tls_server(acceptor, *tls_context.context, response);
            }};

            auto client = merovingian::http::OutboundClient{};
            auto const request = make_localhost_request(port, "localhost", certificate.certificate_pem);
            auto const result = client.perform(request);

            server_thread.join();

            THEN("the request completes successfully with the server's body")
            {
                REQUIRE(result.ok);
                REQUIRE(result.error == merovingian::http::OutboundError::none);
                REQUIRE(result.response.status == 200U);
                REQUIRE(result.response.body == body);
            }
        }
    }
}

SCENARIO("OutboundClient rejects a TLS handshake whose certificate hostname does not match the URL",
         "[http][outbound][tls][integration]")
{
    GIVEN("a TLS server with a CN=localhost certificate and a request that targets a different hostname")
    {
        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();

        auto const response = json_http_response("200 OK", std::string{R"({"ignored":true})"});

        WHEN("OutboundClient::perform is invoked with a hostname that does not match the certificate")
        {
            auto server_thread = std::thread{[&]() {
                run_one_shot_tls_server(acceptor, *tls_context.context, response);
            }};

            auto client = merovingian::http::OutboundClient{};
            // pinned_addresses points the URL host at our loopback server,
            // but the certificate's CN is "localhost", not "wrong.example.org".
            auto const request = make_localhost_request(port, "wrong.example.org", certificate.certificate_pem);
            auto const result = client.perform(request);

            server_thread.join();

            THEN("the call fails closed with a TLS verification error")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.error == merovingian::http::OutboundError::tls_verification_failed);
            }
        }
    }
}

SCENARIO("OutboundClient preserves a percent-encoded federation request target on the wire",
         "[http][outbound][tls][integration][request-target]")
{
    GIVEN("a trusted TLS server and a request URL with encoded Matrix path components")
    {
        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        auto const response = json_http_response("200 OK", std::string{R"({"ok":true})"});
        auto captured_request = std::string{};

        WHEN("OutboundClient::perform sends a federation make_join URL")
        {
            auto server_thread = std::thread{[&]() {
                run_one_shot_tls_server(acceptor, *tls_context.context, response, &captured_request);
            }};

            auto client = merovingian::http::OutboundClient{};
            auto request = merovingian::http::OutboundRequest{};
            request.method = "GET";
            request.url = "https://localhost:" + std::to_string(port) +
                          "/_matrix/federation/v1/make_join/%21room%3Aexample.org/%40alice%3Aremote.example.org?ver=12";
            request.pinned_addresses = {"127.0.0.1"};
            request.connect_timeout_seconds = 5U;
            request.total_timeout_seconds = 10U;
            request.trusted_ca_pem = certificate.certificate_pem;

            auto const result = client.perform(request);

            server_thread.join();

            THEN("the first request line preserves the exact encoded path and query string")
            {
                REQUIRE(result.ok);
                auto const request_line_end = captured_request.find("\r\n");
                REQUIRE(request_line_end != std::string::npos);
                REQUIRE(captured_request.substr(0U, request_line_end) ==
                        "GET /_matrix/federation/v1/make_join/%21room%3Aexample.org/"
                        "%40alice%3Aremote.example.org?ver=12 HTTP/1.1");
            }
        }
    }
}

SCENARIO("OutboundClient rejects an untrusted self-signed certificate", "[http][outbound][tls][integration]")
{
    GIVEN("a TLS server with a self-signed certificate and a request that does not trust it")
    {
        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();

        auto const response = json_http_response("200 OK", std::string{R"({"ignored":true})"});

        WHEN("OutboundClient::perform is invoked without the cert in the trust bundle")
        {
            auto server_thread = std::thread{[&]() {
                run_one_shot_tls_server(acceptor, *tls_context.context, response);
            }};

            auto client = merovingian::http::OutboundClient{};
            // Empty trusted_ca_pem keeps the system trust store in effect,
            // which does not include this freshly generated self-signed cert.
            auto const request = make_localhost_request(port, "localhost", std::string{});
            auto const result = client.perform(request);

            server_thread.join();

            THEN("the call fails closed with a TLS verification error")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.error == merovingian::http::OutboundError::tls_verification_failed);
            }
        }
    }
}

// Regression test for #413: mero_curl_write_header must cap the number of
// stored response headers rather than growing without bound. libcurl imposes
// no default header-count cap, so a hostile federation peer streaming
// hundreds of thousands of headers could otherwise drive an allocation
// failure past the header callback's noexcept boundary and abort the whole
// process. This test proves the cap deterministically aborts the transfer
// well before that: 300 header lines exceeds the 256-header cap.
SCENARIO("OutboundClient aborts a transfer that streams far more response headers than the cap allows",
         "[http][outbound][tls][integration][security]")
{
    GIVEN("a one-shot TLS server that streams 300 response headers, above the stored-header cap")
    {
        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();

        auto const body = std::string{R"({"ignored":true})"};
        auto response = std::string{"HTTP/1.1 200 OK\r\n"};
        for (auto i = 0U; i < 300U; ++i)
        {
            response += "X-Pad-" + std::to_string(i) + ": v\r\n";
        }
        response += "Content-Length: " + std::to_string(body.size());
        response += "\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n";
        response += body;

        WHEN("OutboundClient::perform receives the oversized header stream")
        {
            auto server_thread = std::thread{[&]() {
                run_one_shot_tls_server(acceptor, *tls_context.context, response);
            }};

            auto client = merovingian::http::OutboundClient{};
            auto const request = make_localhost_request(port, "localhost", certificate.certificate_pem);
            auto const result = client.perform(request);

            server_thread.join();

            THEN("the transfer is aborted cleanly rather than the process aborting via bad_alloc/terminate")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.error == merovingian::http::OutboundError::response_too_large);
            }
        }
    }
}

SCENARIO("OutboundClient refuses to follow a 3xx redirect from a federation peer",
         "[http][outbound][tls][integration][redirect]")
{
    GIVEN("a trusted TLS server that returns a 302 redirect")
    {
        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();

        auto const redirect_body = std::string{R"({"redirect":"https://elsewhere.example.org/"})"};
        auto const response =
            json_http_response("302 Found", redirect_body, std::string{"Location: https://elsewhere.example.org/\r\n"});

        WHEN("OutboundClient::perform is invoked against the redirecting server")
        {
            auto server_thread = std::thread{[&]() {
                run_one_shot_tls_server(acceptor, *tls_context.context, response);
            }};

            auto client = merovingian::http::OutboundClient{};
            auto const request = make_localhost_request(port, "localhost", certificate.certificate_pem);
            auto const result = client.perform(request);

            server_thread.join();

            THEN("the response is preserved on the result and the call is marked redirect_rejected")
            {
                REQUIRE_FALSE(result.ok);
                REQUIRE(result.error == merovingian::http::OutboundError::redirect_rejected);
                REQUIRE(result.response.status == 302U);
            }
        }
    }
}

namespace
{

// Open descriptors in this process, counted portably (no /proc): probe each
// number below the soft limit with fcntl(F_GETFD).
[[nodiscard]] auto open_descriptor_count() -> std::size_t
{
    auto const limit = std::min<long>(::sysconf(_SC_OPEN_MAX), 65536L);
    auto count = std::size_t{0U};
    for (auto fd = 0; fd < static_cast<int>(limit); ++fd)
    {
        if (::fcntl(fd, F_GETFD) != -1)
        {
            ++count;
        }
    }
    return count;
}

// Serves one "Connection: close" response from a fresh TLS server on its own
// port and returns whether the call succeeded.
[[nodiscard]] auto call_one_fresh_server(merovingian::http::OutboundClient& client,
                                         merovingian::homeserver::TlsServerContext& tls_context,
                                         std::string const& certificate_pem) -> bool
{
    auto acceptor = merovingian::net::TcpAcceptor{};
    if (!acceptor.bind("127.0.0.1", 0U).ok)
    {
        return false;
    }
    auto const port = acceptor.bound_port();
    auto const response = json_http_response("200 OK", R"({"ok":true})");
    auto server_thread = std::thread{[&]() {
        run_one_shot_tls_server(acceptor, tls_context, response);
    }};
    auto const result = client.perform(make_localhost_request(port, "localhost", certificate_pem));
    server_thread.join();
    return result.ok;
}

} // namespace

// A completed outbound call must leave no descriptor behind on either side.
// The test TLS servers used to leak every accepted socket (TlsConnection only
// borrows its descriptor, and they closed it only when the handshake failed),
// about one per call across the integration suite, until OpenBSD's low
// descriptor limit made later tests unable to open sockets or files. The
// client side matters just as much: OutboundClient keeps one libcurl handle per
// thread for the thread's lifetime, so anything it retained per destination
// would grow with every federation peer a server thread ever talks to.
SCENARIO("OutboundClient does not accumulate descriptors across many destinations on one thread",
         "[http][outbound][tls][integration][descriptor_leak]")
{
    GIVEN("a trusted TLS certificate and a series of servers that each answer once and close")
    {
        auto const certificate = merovingian::tests::tls_mock::write_test_tls_certificate();
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());
        auto client = merovingian::http::OutboundClient{};

        WHEN("one thread calls 8 distinct servers, and then 16 more")
        {
            auto calls_ok = true;
            for (auto index = 0; index < 8; ++index)
            {
                calls_ok = call_one_fresh_server(client, *tls_context.context, certificate.certificate_pem) && calls_ok;
            }
            auto const after_first = open_descriptor_count();
            for (auto index = 0; index < 16; ++index)
            {
                calls_ok = call_one_fresh_server(client, *tls_context.context, certificate.certificate_pem) && calls_ok;
            }
            auto const after_second = open_descriptor_count();

            THEN("every call succeeds and the descriptor count does not grow with the number of destinations")
            {
                REQUIRE(calls_ok);
                REQUIRE(after_second <= after_first);
            }
        }
    }
}
