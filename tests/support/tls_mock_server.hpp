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

#include "merovingian/core/socket_handle.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/identity/identity_client.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "temp_directory.hpp"

#include <catch2/catch_test_macros.hpp>

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
    // Backdated: a notBefore of exactly now made verification fail as "not yet
    // valid" whenever the wall clock stepped back a moment between issuing and
    // verifying (WSL steps its clock), failing whichever scenario was unlucky.
    REQUIRE(X509_gmtime_adj(X509_getm_notBefore(certificate.get()), -3600L) != nullptr);
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
            static_cast<void>(connection.write(path_responses.front().second));
            continue;
        }
        served[chosen] = true;
        static_cast<void>(connection.write(path_responses[chosen].second));
    }
}

// Observable state for run_stalling_tls_server below. `request_received` is set
// once the server has read a complete request; `released` is the test's signal
// that the server may finally answer.
struct StallingTlsServerState final
{
    std::atomic<bool> request_received{false};
    std::atomic<bool> released{false};
};

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
    static_cast<void>(tls_connection.write(http_response));
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

// A trusted mock identity server on a real loopback TLS socket, for the tests
// that exercise the identity-server-delegated 3PID flows (requestToken,
// getValidated3pid, bind). It serves any number of requests until destroyed;
// each response is selected by a substring of the request line (method + path),
// and a request matching none is answered 404 M_UNRECOGNIZED. Responses are
// reusable, not consumed, so a test need not predict how many times the
// homeserver calls an endpoint. The server thread makes no assertions (Catch2 is
// not thread-safe); tests read `requests()` from the main thread.
//
// The certificate CN is the IS host: the homeserver verifies the peer name
// against the URL host, so "localhost" would fail the handshake.
class MockIdentityServer final
{
public:
    using Responses = std::vector<std::pair<std::string, std::string>>;

    explicit MockIdentityServer(Responses responses, std::string host = "is.localhost.test")
        : host_{std::move(host)}
        , responses_{std::move(responses)}
        , certificate_{write_test_tls_certificate(host_)}
        , tls_{merovingian::homeserver::make_tls_server_context(certificate_.certificate_file,
                                                                certificate_.private_key_file)}
    {
        REQUIRE(tls_.ok());
        REQUIRE(acceptor_.bind("127.0.0.1", 0U).ok);
        REQUIRE(acceptor_.bound_port() > 0U);
        thread_ = std::thread{[this] {
            serve();
        }};
    }

    ~MockIdentityServer()
    {
        stop_.store(true);
        if (thread_.joinable())
        {
            thread_.join();
        }
    }

    MockIdentityServer(MockIdentityServer const&) = delete;
    auto operator=(MockIdentityServer const&) -> MockIdentityServer& = delete;
    MockIdentityServer(MockIdentityServer&&) = delete;
    auto operator=(MockIdentityServer&&) -> MockIdentityServer& = delete;

    // The `id_server` value a client sends: host:port.
    [[nodiscard]] auto host_port() const -> std::string
    {
        return host_ + ":" + std::to_string(acceptor_.bound_port());
    }

    [[nodiscard]] auto base_url() const -> std::string
    {
        return "https://" + host_port();
    }

    // A cooperative identity server for tests that only need a 3PID to end up
    // associated with an account: requestToken is answered with the sid
    // "email-sid" or "msisdn-sid", and getValidated3pid for that sid reports the
    // matching entry of `validated` (medium, address) validated at
    // `cooperative_validated_at_ms`. Bind and unbind succeed.
    [[nodiscard]] static auto cooperative_responses(std::vector<std::pair<std::string, std::string>> const& validated)
        -> Responses
    {
        auto responses = Responses{
            {"validate/email/requestToken",  json_http_response("200 OK", R"({"sid":"email-sid"})") },
            {"validate/msisdn/requestToken", json_http_response("200 OK", R"({"sid":"msisdn-sid"})")},
            {"3pid/bind",                    json_http_response("200 OK", "{}")                     },
            {"3pid/unbind",                  json_http_response("200 OK", "{}")                     },
        };
        for (auto const& [medium, address] : validated)
        {
            responses.emplace_back("sid=" + medium + "-sid",
                                   json_http_response("200 OK", R"({"address":")" + address + R"(","medium":")" +
                                                                    medium + R"(","validated_at":)" +
                                                                    std::to_string(cooperative_validated_at_ms) + "}"));
        }
        return responses;
    }

    static constexpr auto cooperative_validated_at_ms = std::uint64_t{1700000000000U};

    // Returns `json_object` (a JSON object literal) with this server named as
    // the request's id_server, together with an IS access token: the pair that
    // delegates a requestToken call to it.
    [[nodiscard]] auto with_identity_server(std::string json_object) const -> std::string
    {
        auto const closing = json_object.rfind('}');
        REQUIRE(closing != std::string::npos);
        json_object.insert(closing, R"(,"id_server":")" + host_port() + R"(","id_access_token":"opaque")");
        return json_object;
    }

    // Marks this server trusted and pins its host to loopback with its
    // self-signed certificate. `Runtime` is a ClientServerRuntime; it is a
    // template parameter so this header stays free of the client-server header.
    template <typename Runtime>
    auto install(Runtime& runtime) const -> void
    {
        auto& identity_server = runtime.homeserver.config.server().identity_server;
        identity_server.default_server = base_url();
        identity_server.trusted_servers = {base_url()};
        runtime.homeserver.test_forced_identity_resolution[host_] =
            merovingian::identity::TestForcedIdentityResolution{{"127.0.0.1"}, certificate_.certificate_pem};
    }

    // Raw bytes of every request received so far, in arrival order.
    [[nodiscard]] auto requests() const -> std::vector<std::string>
    {
        auto const lock = std::lock_guard<std::mutex>{mutex_};
        return captured_;
    }

    // Number of received requests whose bytes contain `needle`.
    [[nodiscard]] auto count_requests(std::string_view needle) const -> std::size_t
    {
        auto count = std::size_t{0U};
        for (auto const& request : requests())
        {
            if (request.find(needle) != std::string::npos)
            {
                ++count;
            }
        }
        return count;
    }

    // Makes the server hold any request whose request line contains `needle`
    // until release_stall() is called (or ten seconds pass, so a failed
    // assertion cannot wedge the suite). stall_seen() turns true once such a
    // request has arrived. Call before the traffic starts.
    auto stall_requests_matching(std::string needle) -> void
    {
        auto const lock = std::lock_guard<std::mutex>{mutex_};
        stall_needle_ = std::move(needle);
    }

    [[nodiscard]] auto stall_seen() const noexcept -> std::atomic<bool> const&
    {
        return stall_seen_;
    }

    auto release_stall() noexcept -> void
    {
        stall_released_.store(true);
    }

private:
    auto serve() noexcept -> void
    {
        while (!stop_.load())
        {
            auto const client_fd = accept_loopback(acceptor_, 50);
            if (client_fd < 0)
            {
                continue;
            }
            auto const owned_client_fd = merovingian::core::SocketHandle{client_fd};
            auto tls_result = merovingian::homeserver::accept_tls_connection(*tls_.context, client_fd, 5000);
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
            }
            auto const request_line = request_bytes.substr(0U, request_bytes.find("\r\n"));
            auto stalls = false;
            {
                auto const lock = std::lock_guard<std::mutex>{mutex_};
                captured_.push_back(request_bytes);
                stalls = !stall_needle_.empty() && request_line.find(stall_needle_) != std::string::npos;
            }
            if (stalls)
            {
                stall_seen_.store(true);
                auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
                while (!stall_released_.load() && !stop_.load() && std::chrono::steady_clock::now() < deadline)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds{5});
                }
            }
            auto response = json_http_response("404 Not Found", R"({"errcode":"M_UNRECOGNIZED","error":"no route"})");
            for (auto const& [needle, canned] : responses_)
            {
                if (request_line.find(needle) != std::string::npos)
                {
                    response = canned;
                    break;
                }
            }
            std::ignore = connection.write(response);
        }
    }

    std::string host_;
    Responses responses_;
    TlsTestCertificate certificate_;
    merovingian::homeserver::TlsServerContextResult tls_;
    merovingian::net::TcpAcceptor acceptor_{};
    std::atomic<bool> stop_{false};
    mutable std::mutex mutex_{};
    std::vector<std::string> captured_{};
    std::string stall_needle_{};
    std::atomic<bool> stall_seen_{false};
    std::atomic<bool> stall_released_{false};
    std::thread thread_{};
};

} // namespace merovingian::tests::tls_mock
