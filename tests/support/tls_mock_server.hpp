// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
//
// Shared TLS mock-server scaffolding for integration/conformance tests that
// need a real local HTTPS peer. Extracted from tests/integration/
// test_join_room_flow.cpp and tests/integration/test_federation_outbound_flow.cpp
// so both the 3PID invite conformance test and the IS bind/unbind integration
// test can stand up a mock identity server without duplicating the OpenSSL
// certificate generation + one-shot TLS server logic. Test-only header; never
// linked into production code.
#pragma once

#include "merovingian/homeserver/tls.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "temp_directory.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sstream>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace merovingian::tests::tls_mock
{

// Joins a mock-server thread on scope exit. A failing REQUIRE unwinds the
// enclosing scope, and destroying a still-joinable std::thread calls
// std::terminate — so an assertion failure would abort the whole test binary
// instead of reporting. Every mock server here has a bounded accept timeout, so
// the join always completes. Joining twice is safe: the explicit join() in the
// happy path leaves the thread non-joinable.
class ScopedThreadJoin final
{
public:
    explicit ScopedThreadJoin(std::thread& thread) noexcept
        : thread_{thread}
    {
    }

    ~ScopedThreadJoin()
    {
        if (thread_.joinable())
        {
            thread_.join();
        }
    }

    ScopedThreadJoin(ScopedThreadJoin const&) = delete;
    auto operator=(ScopedThreadJoin const&) -> ScopedThreadJoin& = delete;
    ScopedThreadJoin(ScopedThreadJoin&&) = delete;
    auto operator=(ScopedThreadJoin&&) -> ScopedThreadJoin& = delete;

private:
    std::thread& thread_;
};

// RAII holder for a self-signed TLS certificate written to a temp directory.
// Move-only; removes the directory on destruction.
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

[[nodiscard]] inline auto read_file_into_string(std::filesystem::path const& path) -> std::string
{
    auto stream = std::ifstream{path, std::ios::binary};
    auto buffer = std::ostringstream{};
    buffer << stream.rdbuf();
    return buffer.str();
}

// Portable across OpenSSL 3 and LibreSSL (OpenBSD) — mirrors the implementation
// in test_federation_outbound_flow.cpp / test_join_room_flow.cpp exactly.
[[nodiscard]] inline auto generate_rsa_key(int bits) -> EVP_PKEY*
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

// Generates a self-signed certificate for `common_name`. The name must match the
// host in the URL the client requests, or peer verification fails — see the
// negative scenario in tests/integration/test_federation_outbound_flow.cpp
// ("a request that targets a different hostname"). No SAN is set, so OpenSSL
// falls back to CN matching.
[[nodiscard]] inline auto write_test_tls_certificate(std::string const& common_name = "localhost") -> TlsTestCertificate
{
    static auto counter = std::uint32_t{0U};
    auto const directory = merovingian::tests::temporary_directory() /
                           ("merovingian-tls-mock-" + std::to_string(::getpid()) + "-" + std::to_string(++counter));
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
    auto const* common_name_bytes = reinterpret_cast<unsigned char const*>(common_name.c_str());
    REQUIRE(X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, common_name_bytes, -1, -1, 0) == 1);
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

[[nodiscard]] inline auto accept_loopback(merovingian::net::TcpAcceptor& acceptor, int timeout_ms) -> int
{
    auto pollfd_entry = ::pollfd{acceptor.fd(), POLLIN, 0};
    auto const ready = ::poll(&pollfd_entry, 1U, timeout_ms);
    if (ready <= 0)
    {
        return -1;
    }
    return ::accept(acceptor.fd(), nullptr, nullptr);
}

[[nodiscard]] inline auto json_http_response(std::string const& status_line, std::string const& body) -> std::string
{
    auto response = std::string{"HTTP/1.1 "};
    response += status_line;
    response += "\r\nContent-Length: ";
    response += std::to_string(body.size());
    response += "\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n";
    response += body;
    return response;
}

// One-shot TLS server: waits for a single connection, completes the handshake,
// drains some request bytes, writes the configured response, and closes. The
// server thread joins quickly even when the client aborts because both the
// accept poll and the TLS handshake carry bounded timeouts. If
// `captured_request` is non-null the raw request bytes are stored there.
inline auto run_one_shot_tls_server(merovingian::net::TcpAcceptor& acceptor,
                                    merovingian::homeserver::TlsServerContext& tls_context,
                                    std::string const& http_response, std::string* captured_request = nullptr) noexcept
    -> void
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

// Multi-shot path-dispatching TLS server. Loops `responses.size()` iterations,
// each accepting one TLS connection, reading until \r\n\r\n, and writing the
// response selected by matching a path substring in the request bytes against
// the keys of `responses`. When a path key is not found in the request, the
// first unused response is written (robust to unexpected ordering). Captures
// every received request into `captured_requests` (one entry per iteration,
// in arrival order) when non-null.
inline auto run_path_dispatch_tls_server(merovingian::net::TcpAcceptor& acceptor,
                                         merovingian::homeserver::TlsServerContext& tls_context,
                                         std::vector<std::pair<std::string, std::string>> const& path_responses,
                                         std::vector<std::string>* captured_requests = nullptr) noexcept -> void
{
    auto served = std::vector<bool>(path_responses.size(), false);
    for (auto iteration = std::size_t{0U}; iteration < path_responses.size(); ++iteration)
    {
        auto const client_fd = accept_loopback(acceptor, 10000);
        if (client_fd < 0)
        {
            return;
        }
        auto tls_result = merovingian::homeserver::accept_tls_connection(tls_context, client_fd, 5000);
        if (!tls_result.connection.has_value())
        {
            ::close(client_fd);
            continue;
        }
        auto& connection = *tls_result.connection;
        auto buffer = std::array<char, 8192>{};
        auto request_bytes = std::string{};
        while (request_bytes.find("\r\n\r\n") == std::string::npos)
        {
            auto const bytes_read = connection.read(buffer.data(), buffer.size());
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
        if (captured_requests != nullptr)
        {
            captured_requests->push_back(request_bytes);
        }
        // Select the response whose path substring appears in the request. Prefer
        // an unserved match; fall back to the first unserved response otherwise.
        auto chosen = path_responses.size();
        for (auto index = std::size_t{0U}; index < path_responses.size(); ++index)
        {
            if (!served[index] && request_bytes.find(path_responses[index].first) != std::string::npos)
            {
                chosen = index;
                break;
            }
        }
        if (chosen == path_responses.size())
        {
            for (auto index = std::size_t{0U}; index < path_responses.size(); ++index)
            {
                if (!served[index])
                {
                    chosen = index;
                    break;
                }
            }
        }
        if (chosen == path_responses.size())
        {
            static_cast<void>(connection.write(path_responses.front().second));
            continue;
        }
        served[chosen] = true;
        static_cast<void>(connection.write(path_responses[chosen].second));
    }
}

} // namespace merovingian::tests::tls_mock
