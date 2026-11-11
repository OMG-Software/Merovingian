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

#include "EvpPkeyDeleter.hpp"
#include "FileDeleter.hpp"
#include "StallingTlsServerState.hpp"
#include "TlsTestCertificate.hpp"
#include "X509Deleter.hpp"
#include "X509ExtensionDeleter.hpp"
#include "X509NameDeleter.hpp"
#include "merovingian/core/FileDescriptor.hpp"
#include "merovingian/core/SocketHandle.hpp"
#include "merovingian/homeserver/TlsServerContext.hpp"
#include "merovingian/homeserver/Tls.hpp"
#include "merovingian/net/TcpAcceptor.hpp"
#include "TempDirectory.hpp"

#include <catch2/catch_test_macros.hpp>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

namespace merovingian::tests::tls_mock
{

// Opens `path` for writing as an owner-only (0600) file. `std::fopen` would create it with 0666 less the umask, so
// the private key would be open to other users until the chmod below (CodeQL cpp/world-writable-file-creation);
// the fchmod also narrows a file left over from an earlier run.
[[nodiscard]] inline auto open_owner_only_for_write(std::string const& path) -> std::unique_ptr<std::FILE, FileDeleter>
{
    auto descriptor = merovingian::core::FileDescriptor{
        ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR)};
    if (!descriptor.valid() || ::fchmod(descriptor.get(), S_IRUSR | S_IWUSR) != 0)
    {
        return {};
    }
    auto file = std::unique_ptr<std::FILE, FileDeleter>{::fdopen(descriptor.get(), "wb")};
    if (file != nullptr)
    {
        // The FILE now owns the descriptor and closes it.
        std::ignore = descriptor.release();
    }
    return file;
}

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

// A one-entry name, CN=`common_name`. Built apart from any certificate: OpenSSL 4 returns a certificate's names
// as const, and OpenSSL 3 and LibreSSL take a name built here, so this one form builds on all three.
[[nodiscard]] inline auto make_common_name(std::string const& common_name) -> std::unique_ptr<X509_NAME, X509NameDeleter>
{
    auto name = std::unique_ptr<X509_NAME, X509NameDeleter>{X509_NAME_new()};
    REQUIRE(name != nullptr);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    auto const* bytes = reinterpret_cast<unsigned char const*>(common_name.c_str());
    REQUIRE(X509_NAME_add_entry_by_txt(name.get(), "CN", MBSTRING_ASC, bytes, -1, -1, 0) == 1);
    return name;
}

// An unsigned X.509 v3 certificate for `key`, named `subject` and issued by `issuer`, valid from an hour ago to an
// hour from now. The caller adds extensions and signs it.
[[nodiscard]] inline auto make_v3_certificate(EVP_PKEY* key, X509_NAME* subject, X509_NAME* issuer, int serial)
    -> std::unique_ptr<X509, X509Deleter>
{
    auto certificate = std::unique_ptr<X509, X509Deleter>{X509_new()};
    REQUIRE(certificate != nullptr);
    // The version field holds the number less one: 2 is v3, which extensions require.
    REQUIRE(X509_set_version(certificate.get(), 2L) == 1);
    REQUIRE(ASN1_INTEGER_set(X509_get_serialNumber(certificate.get()), serial) == 1);
    // Backdated: a notBefore of exactly now made verification fail as "not yet
    // valid" whenever the wall clock stepped back a moment between issuing and
    // verifying (WSL steps its clock), failing whichever scenario was unlucky.
    REQUIRE(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -3600L) != nullptr);
    REQUIRE(X509_gmtime_adj(X509_getm_notAfter(certificate.get()), 3600L) != nullptr);
    REQUIRE(X509_set_pubkey(certificate.get(), key) == 1);
    REQUIRE(X509_set_subject_name(certificate.get(), subject) == 1);
    REQUIRE(X509_set_issuer_name(certificate.get(), issuer) == 1);
    return certificate;
}

// Adds one extension to `certificate`, written as in an OpenSSL configuration file ("critical,CA:FALSE"). `issuer`
// is the certificate whose key identifier an authorityKeyIdentifier names.
inline auto add_extension(X509* certificate, X509* issuer, int nid, char const* value) -> void
{
    auto context = X509V3_CTX{};
    X509V3_set_ctx(&context, issuer, certificate, nullptr, nullptr, 0);
    auto const extension =
        std::unique_ptr<X509_EXTENSION, X509ExtensionDeleter>{X509V3_EXT_conf_nid(nullptr, &context, nid, value)};
    REQUIRE(extension != nullptr);
    REQUIRE(X509_add_ext(certificate, extension.get(), -1) == 1);
}

// The subjectAltName value naming `host`: an IP address entry for a literal address, a DNS entry otherwise.
[[nodiscard]] inline auto subject_alt_name_for(std::string const& host) -> std::string
{
    auto const is_ip_literal =
        host.find(':') != std::string::npos ||
        (!host.empty() && host.find_first_not_of("0123456789.") == std::string::npos);
    return (is_ip_literal ? "IP:" : "DNS:") + host;
}

// Writes `certificate` as PEM to an owner-only file at `path`.
inline auto write_certificate_pem(std::string const& path, X509* certificate) -> void
{
    auto file = open_owner_only_for_write(path);
    REQUIRE(file != nullptr);
    REQUIRE(PEM_write_X509(file.get(), certificate) == 1);
}

// Issues a server certificate for `common_name` from a throwaway test CA made for this call. The server presents
// `certificate_file`; a client trusts `certificate_pem`, which is the CA, never the server certificate itself.
//
// A self-signed server certificate trusted as its own anchor passed OpenSSL's verification, but not Ubuntu's: from
// Ubuntu 26.10 libcurl also verifies through upki (rustls-webpki), which accepts a server certificate only when a
// trusted CA issued it, and only as a v3 end-entity certificate (ADR-0650). So the server certificate is CA:FALSE
// with serverAuth and a subjectAltName for the name, and the CA is CA:TRUE and may sign certificates. The name must
// match the host in the URL the client requests, or peer verification fails; see the negative scenario in
// tests/integration/test_federation_outbound_flow.cpp ("a request that targets a different hostname").
[[nodiscard]] inline auto write_test_tls_certificate(std::string const& common_name = "localhost") -> TlsTestCertificate
{
    static auto counter = std::uint32_t{0U};
    auto const directory = merovingian::tests::temporary_directory() /
                           ("merovingian-tls-mock-" + std::to_string(::getpid()) + "-" + std::to_string(++counter));
    std::filesystem::create_directories(directory);

    auto const ca_key = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>{generate_rsa_key(2048)};
    REQUIRE(ca_key != nullptr);
    auto const ca_name = make_common_name("Merovingian test CA");
    auto const ca = make_v3_certificate(ca_key.get(), ca_name.get(), ca_name.get(), 1);
    add_extension(ca.get(), ca.get(), NID_basic_constraints, "critical,CA:TRUE");
    add_extension(ca.get(), ca.get(), NID_key_usage, "critical,keyCertSign,cRLSign");
    add_extension(ca.get(), ca.get(), NID_subject_key_identifier, "hash");
    REQUIRE(X509_sign(ca.get(), ca_key.get(), EVP_sha256()) > 0);

    auto const key = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>{generate_rsa_key(2048)};
    REQUIRE(key != nullptr);
    auto const subject = make_common_name(common_name);
    auto const certificate = make_v3_certificate(key.get(), subject.get(), ca_name.get(), 2);
    add_extension(certificate.get(), ca.get(), NID_basic_constraints, "critical,CA:FALSE");
    add_extension(certificate.get(), ca.get(), NID_key_usage, "critical,digitalSignature,keyEncipherment");
    add_extension(certificate.get(), ca.get(), NID_ext_key_usage, "serverAuth");
    add_extension(certificate.get(), ca.get(), NID_subject_alt_name, subject_alt_name_for(common_name).c_str());
    add_extension(certificate.get(), ca.get(), NID_subject_key_identifier, "hash");
    add_extension(certificate.get(), ca.get(), NID_authority_key_identifier, "keyid");
    REQUIRE(X509_sign(certificate.get(), ca_key.get(), EVP_sha256()) > 0);

    auto output = TlsTestCertificate{};
    output.directory = directory;
    output.certificate_file = (directory / "server.pem").string();
    output.private_key_file = (directory / "server.key").string();
    auto const ca_file = (directory / "ca.pem").string();

    write_certificate_pem(output.certificate_file, certificate.get());
    write_certificate_pem(ca_file, ca.get());
    {
        auto key_file = open_owner_only_for_write(output.private_key_file);
        REQUIRE(key_file != nullptr);
        REQUIRE(PEM_write_PrivateKey(key_file.get(), key.get(), nullptr, nullptr, 0, nullptr, nullptr) == 1);
    }
    // ISO-7: the server reads its TLS key only from an owner-read-only file.
    std::filesystem::permissions(output.private_key_file, std::filesystem::perms::owner_read);

    output.certificate_pem = read_file_into_string(ca_file);
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
        // Owns the accepted descriptor: TlsConnection only borrows it, so without
        // this every served connection stayed open for the rest of the run.
        auto const owned_client_fd = merovingian::core::SocketHandle{client_fd};
        auto tls_result = merovingian::homeserver::accept_tls_connection(tls_context, client_fd, 5000);
        if (!tls_result.connection.has_value())
        {
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
            std::ignore = connection.write(path_responses.front().second);
            continue;
        }
        served[chosen] = true;
        std::ignore = connection.write(path_responses[chosen].second);
    }
}

// One-shot TLS server that accepts a request, announces that it has arrived,
// and then holds the connection open until the test releases it — modelling a
// peer that is reachable but slow. It exists so a test can observe what the
// rest of the process is able to do while an outbound call is still in flight.
//
// The stall is bounded: the server answers anyway once `max_stall` elapses, so
// the thread always terminates and a failed assertion is reported as a failure
// rather than escalating into a whole-suite timeout.
inline auto run_stalling_tls_server(merovingian::net::TcpAcceptor& acceptor,
                                    merovingian::homeserver::TlsServerContext& tls_context,
                                    StallingTlsServerState& state, std::string const& http_response,
                                    std::chrono::milliseconds max_stall) noexcept -> void
{
    auto const client_fd = accept_loopback(acceptor, 5000);
    if (client_fd < 0)
    {
        state.request_received.store(true);
        return;
    }
    // Owns the accepted descriptor: TlsConnection only borrows it, so without
    // this every served connection stayed open for the rest of the run.
    auto const owned_client_fd = merovingian::core::SocketHandle{client_fd};
    auto tls_result = merovingian::homeserver::accept_tls_connection(tls_context, client_fd, 5000);
    if (!tls_result.connection.has_value())
    {
        state.request_received.store(true);
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
    state.request_received.store(true);
    auto const deadline = std::chrono::steady_clock::now() + max_stall;
    while (!state.released.load() && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    std::ignore = tls_connection.write(http_response);
}

// Spins until `flag` is set or `timeout` elapses. Returns whether the flag was
// observed set, so the caller can assert on it from the main thread.
[[nodiscard]] inline auto wait_for_flag(std::atomic<bool> const& flag, std::chrono::milliseconds timeout) -> bool
{
    auto const deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (flag.load())
        {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{5});
    }
    return flag.load();
}

} // namespace merovingian::tests::tls_mock

// The shim below is deliberately last: MockIdentityServer uses the functions above.
