// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/temp_directory.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/http/outbound_client.hpp"
#include "merovingian/net/tcp_acceptor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <utility>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace
{

struct TlsTestCertificate final
{
    std::filesystem::path directory{};
    std::string certificate_file{};
    std::string private_key_file{};
    std::string certificate_pem{};

    TlsTestCertificate() = default;

    ~TlsTestCertificate()
    {
        auto ignored = std::error_code{};
        std::filesystem::remove_all(directory, ignored);
    }

    TlsTestCertificate(TlsTestCertificate const&) = delete;
    auto operator=(TlsTestCertificate const&) -> TlsTestCertificate& = delete;

    TlsTestCertificate(TlsTestCertificate&& other) noexcept
        : directory{std::move(other.directory)}
        , certificate_file{std::move(other.certificate_file)}
        , private_key_file{std::move(other.private_key_file)}
        , certificate_pem{std::move(other.certificate_pem)}
    {
        other.directory.clear();
    }

    auto operator=(TlsTestCertificate&& other) noexcept -> TlsTestCertificate&
    {
        if (this != &other)
        {
            auto ignored = std::error_code{};
            std::filesystem::remove_all(directory, ignored);
            directory = std::move(other.directory);
            certificate_file = std::move(other.certificate_file);
            private_key_file = std::move(other.private_key_file);
            certificate_pem = std::move(other.certificate_pem);
            other.directory.clear();
        }
        return *this;
    }
};

struct EvpPkeyDeleter final
{
    auto operator()(EVP_PKEY* key) const noexcept -> void
    {
        EVP_PKEY_free(key);
    }
};

struct X509Deleter final
{
    auto operator()(X509* certificate) const noexcept -> void
    {
        X509_free(certificate);
    }
};

struct FileDeleter final
{
    auto operator()(std::FILE* file) const noexcept -> void
    {
        if (file != nullptr)
        {
            static_cast<void>(std::fclose(file));
        }
    }
};

[[nodiscard]] auto read_file_into_string(std::filesystem::path const& path) -> std::string
{
    auto stream = std::ifstream{path, std::ios::binary};
    auto buffer = std::ostringstream{};
    buffer << stream.rdbuf();
    return buffer.str();
}

// Generates an RSA key portably across OpenSSL 3 and LibreSSL. EVP_RSA_gen is an
// OpenSSL-3-only convenience wrapper absent from LibreSSL (OpenBSD), so use the
// EVP_PKEY_CTX keygen path that both provide.
[[nodiscard]] auto generate_rsa_key(int bits) -> EVP_PKEY*
{
    auto* const context = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (context == nullptr)
    {
        return nullptr;
    }
    EVP_PKEY* key = nullptr;
    if (EVP_PKEY_keygen_init(context) > 0 && EVP_PKEY_CTX_set_rsa_keygen_bits(context, bits) > 0)
    {
        EVP_PKEY_keygen(context, &key);
    }
    EVP_PKEY_CTX_free(context);
    return key;
}

// Builds a self-signed RSA certificate on disk and returns the file paths plus
// the certificate's PEM contents so tests can hand the PEM to OutboundRequest
// as a trust anchor without re-reading the file.
[[nodiscard]] auto write_test_tls_certificate() -> TlsTestCertificate
{
    static auto counter = std::uint32_t{0U};
    auto const directory = merovingian::tests::temporary_directory() /
                           ("merovingian-outbound-tls-" + std::to_string(::getpid()) + "-" + std::to_string(++counter));
    std::filesystem::create_directories(directory);

    auto key = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>{generate_rsa_key(2048)};
    REQUIRE(key != nullptr);

    auto certificate = std::unique_ptr<X509, X509Deleter>{X509_new()};
    REQUIRE(certificate != nullptr);
    REQUIRE(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), 1L) == 1);
    REQUIRE(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), 0L) != nullptr);
    REQUIRE(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600L) != nullptr);
    REQUIRE(X509_set_pubkey(certificate.get(), key.get()) == 1);

    auto* subject = X509_get_subject_name(certificate.get());
    REQUIRE(subject != nullptr);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto const* common_name = reinterpret_cast<unsigned char const*>("localhost");
    REQUIRE(X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, common_name, -1, -1, 0) == 1);
    REQUIRE(X509_set_issuer_name(certificate.get(), subject) == 1);
    REQUIRE(X509_sign(certificate.get(), key.get(), EVP_sha256()) > 0);

    auto output = TlsTestCertificate{};
    output.directory = directory;
    output.certificate_file = (directory / "server.pem").string();
    output.private_key_file = (directory / "server.key").string();

    auto cert_file = std::unique_ptr<std::FILE, FileDeleter>{std::fopen(output.certificate_file.c_str(), "wb")};
    REQUIRE(cert_file != nullptr);
    REQUIRE(PEM_write_X509(cert_file.get(), certificate.get()) == 1);

    auto key_file = std::unique_ptr<std::FILE, FileDeleter>{std::fopen(output.private_key_file.c_str(), "wb")};
    REQUIRE(key_file != nullptr);
    REQUIRE(PEM_write_PrivateKey(key_file.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1);

    // Flush the FILE handles before reading the cert back as a string.
    cert_file.reset();
    key_file.reset();

    output.certificate_pem = read_file_into_string(output.certificate_file);
    return output;
}

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
    auto tls_result = merovingian::homeserver::accept_tls_connection(tls_context, client_fd, 5000);
    if (!tls_result.connection.has_value())
    {
        ::close(client_fd);
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
    static_cast<void>(tls_connection.write(http_response));
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
        auto const certificate = write_test_tls_certificate();
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
        auto const certificate = write_test_tls_certificate();
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
        auto const certificate = write_test_tls_certificate();
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
        auto const certificate = write_test_tls_certificate();
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

SCENARIO("OutboundClient refuses to follow a 3xx redirect from a federation peer",
         "[http][outbound][tls][integration][redirect]")
{
    GIVEN("a trusted TLS server that returns a 302 redirect")
    {
        auto const certificate = write_test_tls_certificate();
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
