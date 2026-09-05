// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/core/socket_handle.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/http_server.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/net/shutdown_signal.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "merovingian/net/thread_pool.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    // A runtime refuses to mint a signing secret it cannot encrypt at rest
    // (0.12.5 audit, finding 1), so every fixture needs a master key.
    security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},           merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},         security,
        merovingian::config::ClientRateLimitsConfig{}, merovingian::config::LogModulesConfig{},
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

auto send_all_tls(SSL& connection, std::string_view data) -> bool
{
    auto remaining = data;
    while (!remaining.empty())
    {
        auto written = std::size_t{0U};
        if (SSL_write_ex(&connection, remaining.data(), remaining.size(), &written) != 1 || written == 0U)
        {
            return false;
        }
        remaining.remove_prefix(written);
    }
    return true;
}

#if defined(__linux__)
// Finds the server-side fd for a still-open accepted connection by matching
// its peer port against `client_local_port` (the connecting client socket's
// own local port, i.e. the port the server sees as its peer). There is no
// production hook that exposes the accepted fd directly, so this scans the
// process's own fd table — reliable as long as the connection is still open
// when called, which the caller ensures by holding the request incomplete.
// Linux-only: relies on /proc/self/fd, which isn't guaranteed on the
// project's supported BSDs (see the SCENARIO below that uses this).
[[nodiscard]] auto find_accepted_socket_fd(std::uint16_t client_local_port) -> int
{
    auto* dir = ::opendir("/proc/self/fd");
    if (dir == nullptr)
    {
        return -1;
    }
    auto found = -1;
    while (auto* entry = ::readdir(dir))
    {
        auto const name = std::string_view{entry->d_name};
        if (name == "." || name == "..")
        {
            continue;
        }
        auto candidate = 0;
        if (std::from_chars(name.data(), name.data() + name.size(), candidate).ec != std::errc{})
        {
            continue;
        }
        auto peer = sockaddr_in{};
        auto peer_len = socklen_t{sizeof(peer)};
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        if (::getpeername(candidate, reinterpret_cast<sockaddr*>(&peer), &peer_len) != 0)
        {
            continue;
        }
        if (peer.sin_family == AF_INET && ntohs(peer.sin_port) == client_local_port)
        {
            found = candidate;
            break;
        }
    }
    ::closedir(dir);
    return found;
}
#endif // defined(__linux__)

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

// Readers that consume exactly one Content-Length framed response per call,
// keeping any pipelined bytes buffered for the next call. With HTTP
// keep-alive the server no longer closes the connection after a response, so
// "read until EOF" cannot delimit one response — the frame boundary comes from
// the Content-Length header the server always writes.
struct PlainResponseReader final
{
    std::string pending{};
};

struct TlsResponseReader final
{
    std::string pending{};
};

// Returns the total byte length (head + body) of the first complete
// Content-Length framed response in `pending`, or std::string::npos when the
// buffered bytes do not yet contain a complete response.
[[nodiscard]] auto framed_response_length(std::string const& pending) -> std::size_t
{
    constexpr auto npos = std::string::npos;
    auto const head_end = pending.find("\r\n\r\n");
    if (head_end == npos)
    {
        return npos;
    }
    constexpr auto length_prefix = std::string_view{"\r\nContent-Length: "};
    auto const length_header = pending.find(length_prefix);
    if (length_header == npos || length_header > head_end)
    {
        return npos;
    }
    auto const digits_begin = length_header + length_prefix.size();
    auto const digits_end = pending.find("\r\n", digits_begin);
    if (digits_end == npos || digits_end > head_end)
    {
        return npos;
    }
    auto length = std::size_t{0U};
    for (auto index = digits_begin; index < digits_end; ++index)
    {
        auto const character = pending[index];
        if (character < '0' || character > '9')
        {
            return npos;
        }
        length = (length * 10U) + static_cast<std::size_t>(character - '0');
    }
    return head_end + 4U + length;
}

// Reads one framed response from the socket. Returns the complete response
// (status line, headers, body) or an empty string when the peer closes
// before a complete response arrives. Bytes belonging to a following
// (pipelined) response stay buffered in the reader.
[[nodiscard]] auto receive_response(int fd, PlainResponseReader& reader) -> std::string
{
    auto buffer = std::array<char, 4096U>{};
    while (true)
    {
        auto const total = framed_response_length(reader.pending);
        if (total != std::string::npos && reader.pending.size() >= total)
        {
            auto response = reader.pending.substr(0U, total);
            reader.pending.erase(0U, total);
            return response;
        }
        auto const received = ::recv(fd, buffer.data(), buffer.size(), 0);
        if (received <= 0)
        {
            // Peer closed (or errored) before a complete response: surface
            // whatever was buffered so assertions name what was received.
            auto partial = std::move(reader.pending);
            reader.pending.clear();
            return partial;
        }
        reader.pending.append(buffer.data(), static_cast<std::size_t>(received));
    }
}

[[nodiscard]] auto receive_tls_response(SSL& connection, TlsResponseReader& reader) -> std::string
{
    auto buffer = std::array<char, 4096U>{};
    while (true)
    {
        auto const total = framed_response_length(reader.pending);
        if (total != std::string::npos && reader.pending.size() >= total)
        {
            auto response = reader.pending.substr(0U, total);
            reader.pending.erase(0U, total);
            return response;
        }
        auto received = std::size_t{0U};
        if (SSL_read_ex(&connection, buffer.data(), buffer.size(), &received) != 1 || received == 0U)
        {
            auto partial = std::move(reader.pending);
            reader.pending.clear();
            return partial;
        }
        reader.pending.append(buffer.data(), received);
    }
}

// Waits until the socket is readable, then reports whether the peer has
// closed it (recv returns 0). Bounded: returns false if nothing arrives
// within `timeout_ms`, so a server that never closes cannot hang a test.
[[nodiscard]] auto peer_closed_within(int fd, int timeout_ms) -> bool
{
    auto entry = pollfd{};
    entry.fd = fd;
    entry.events = POLLIN;
    auto const poll_result = ::poll(&entry, 1U, timeout_ms);
    if (poll_result <= 0 || (entry.revents & POLLIN) == 0)
    {
        return false;
    }
    auto probe = std::array<char, 1U>{};
    return ::recv(fd, probe.data(), probe.size(), MSG_PEEK | MSG_DONTWAIT) == 0;
}

struct TlsTestCertificate final
{
    std::filesystem::path directory{};
    std::string certificate_file{};
    std::string private_key_file{};

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

// Generates an RSA key portably across OpenSSL 3 and LibreSSL (OpenBSD ships
// LibreSSL, which lacks the OpenSSL-3-only EVP_RSA_gen wrapper).
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

[[nodiscard]] auto write_test_tls_certificate() -> TlsTestCertificate
{
    static auto counter = std::uint32_t{0U};
    auto const directory = merovingian::tests::temporary_directory() /
                           ("merovingian-tls-" + std::to_string(::getpid()) + "-" + std::to_string(++counter));
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

    return output;
}

struct SslContextDeleter final
{
    auto operator()(SSL_CTX* context) const noexcept -> void
    {
        SSL_CTX_free(context);
    }
};

struct SslDeleter final
{
    auto operator()(SSL* connection) const noexcept -> void
    {
        SSL_free(connection);
    }
};

} // namespace

SCENARIO("merovingian-server accepts an HTTP request and returns the router's response over a TCP socket",
         "[homeserver][http][listener][integration]")
{
    GIVEN("a started runtime and a TCP acceptor bound to an ephemeral loopback port")
    {
        auto const config = registration_enabled_config();
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto shutdown = merovingian::net::ShutdownSignal{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        // The pool is declared after the runtime so it is destroyed first.
        // ~ThreadPool joins the workers, and a worker can still be inside
        // serve_connection holding a ConnectionContext that references
        // `runtime` -- ASan caught exactly that read landing in this frame
        // after it had gone. Each WHEN block also stops the pool explicitly
        // (see below), so this ordering is the backstop rather than the only
        // thing standing between a worker and a destroyed runtime.
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{4U};

        WHEN("a client sends an HTTP/1.1 request to an unknown route")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_http(acceptor, runtime, shutdown, stats,
                                                    merovingian::homeserver::HttpDispatchMode::local_router, pool);
            }};

            auto const client_fd = connect_loopback(port);
            REQUIRE(client_fd >= 0);

            auto const request =
                std::string{"GET /no-such-route HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"};
            REQUIRE(send_all(client_fd, request));

            auto const response = receive_until_close(client_fd);
            ::close(client_fd);

            shutdown.fire();
            server_thread.join();
            // Joins the connection workers here, not during unwind: the client
            // sockets are already closed at this point so a parked worker sees
            // EOF and exits promptly, and if one ever does not, the failure
            // names this line instead of timing out the whole binary.
            pool.request_stop();

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

#if defined(__linux__)
// This scenario's fd-discovery technique (find_accepted_socket_fd) depends on
// /proc/self/fd, which is Linux-specific: none of the project's supported
// BSDs guarantee it (OpenBSD removed procfs outright; FreeBSD/NetBSD don't
// mount it by default in CI). The production behaviour being verified
// (accept4(..., SOCK_CLOEXEC) in http_server.cpp) is itself fully portable
// across all four platforms — only this test's verification mechanism is
// Linux-only.
SCENARIO("merovingian-server marks accepted client sockets close-on-exec",
         "[homeserver][http][listener][integration][security]")
{
    GIVEN("a started runtime and a TCP acceptor bound to an ephemeral loopback port")
    {
        auto const config = registration_enabled_config();
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto shutdown = merovingian::net::ShutdownSignal{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        // The pool is declared after the runtime so it is destroyed first.
        // ~ThreadPool joins the workers, and a worker can still be inside
        // serve_connection holding a ConnectionContext that references
        // `runtime` -- ASan caught exactly that read landing in this frame
        // after it had gone. Each WHEN block also stops the pool explicitly
        // (see below), so this ordering is the backstop rather than the only
        // thing standing between a worker and a destroyed runtime.
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{4U};

        WHEN("a client connects and holds the connection open with an incomplete request")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_http(acceptor, runtime, shutdown, stats,
                                                    merovingian::homeserver::HttpDispatchMode::local_router, pool);
            }};
            // A std::thread destroyed while still joinable calls std::terminate.
            // If a REQUIRE below throws to unwind this WHEN block, this guard's
            // destructor still runs (raising shutdown and joining) before
            // server_thread's own destructor gets a chance to abort the process
            // — a failed assertion should report as a failed test, not a SIGABRT
            // that also takes out the rest of the test binary.
            struct ServerThreadGuard final
            {
                merovingian::net::ShutdownSignal& shutdown_signal;
                std::thread& thread;

                ~ServerThreadGuard()
                {
                    shutdown_signal.fire();
                    if (thread.joinable())
                    {
                        thread.join();
                    }
                }
            } server_thread_guard{shutdown, server_thread};

            auto const client_fd = connect_loopback(port);
            REQUIRE(client_fd >= 0);

            auto client_local = sockaddr_in{};
            auto client_local_len = socklen_t{sizeof(client_local)};
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            REQUIRE(::getsockname(client_fd, reinterpret_cast<sockaddr*>(&client_local), &client_local_len) == 0);
            auto const client_local_port = ntohs(client_local.sin_port);

            // Deliberately incomplete: no terminating blank line, so the
            // server's request-head parser keeps waiting for more data and
            // the accepted connection (and its fd) stays open long enough to
            // inspect from this test.
            REQUIRE(send_all(client_fd, "GET /no-such-route HTTP/1.1\r\nHost: localhost\r\n"));

            auto accepted_fd = -1;
            // Poll rather than sleep-once: the accept loop runs on its own
            // thread and there is no synchronous "connection accepted" signal
            // to wait on directly.
            for (auto attempt = 0; attempt < 200 && accepted_fd < 0; ++attempt)
            {
                accepted_fd = find_accepted_socket_fd(client_local_port);
                if (accepted_fd < 0)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds{5});
                }
            }
            REQUIRE(accepted_fd >= 0);

            auto const flags = ::fcntl(accepted_fd, F_GETFD, 0);
            REQUIRE(flags >= 0);

            // Complete the request so the server thread can finish and be
            // joined cleanly by server_thread_guard's destructor below.
            REQUIRE(send_all(client_fd, "\r\n"));
            auto reader = PlainResponseReader{};
            std::ignore = receive_response(client_fd, reader);
            ::close(client_fd);

            THEN("the accepted socket carries FD_CLOEXEC")
            {
                // Spec (src/net/AGENTS.md): "All sockets must be opened with
                // O_CLOEXEC / SOCK_CLOEXEC. File descriptors must not leak
                // across fork()/exec()." An accepted client socket without
                // this flag would be inherited by any worker subprocess
                // spawned (posix_spawn/fork) while the connection is open.
                REQUIRE((flags & FD_CLOEXEC) != 0);
            }
        }
    }
}
#endif // defined(__linux__)

SCENARIO("merovingian-server accepts Matrix JSON requests over a configured TLS listener",
         "[homeserver][http][listener][tls][integration]")
{
    GIVEN("a TLS server context and a registration-enabled runtime")
    {
        auto const certificate = write_test_tls_certificate();
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());

        auto const config = registration_enabled_config();
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto shutdown = merovingian::net::ShutdownSignal{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        // The pool is declared after the runtime so it is destroyed first.
        // ~ThreadPool joins the workers, and a worker can still be inside
        // serve_connection holding a ConnectionContext that references
        // `runtime` -- ASan caught exactly that read landing in this frame
        // after it had gone. Each WHEN block also stops the pool explicitly
        // (see below), so this ordering is the backstop rather than the only
        // thing standing between a worker and a destroyed runtime.
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{4U};

        WHEN("a TLS client sends Matrix JSON registration over TCP")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_tls_http(*tls_context.context, acceptor, runtime, shutdown, stats,
                                                        merovingian::homeserver::HttpDispatchMode::client_server, pool);
            }};

            auto client_context = std::unique_ptr<SSL_CTX, SslContextDeleter>{SSL_CTX_new(TLS_client_method())};
            REQUIRE(client_context != nullptr);
            SSL_CTX_set_verify(client_context.get(), SSL_VERIFY_NONE, nullptr);

            auto const client_fd = connect_loopback(port);
            REQUIRE(client_fd >= 0);
            auto client_socket = merovingian::core::SocketHandle{client_fd};
            auto client_tls = std::unique_ptr<SSL, SslDeleter>{SSL_new(client_context.get())};
            REQUIRE(client_tls != nullptr);
            REQUIRE(SSL_set_fd(client_tls.get(), client_socket.native_handle()) == 1);
            REQUIRE(SSL_connect(client_tls.get()) == 1);

            auto const body = merovingian::tests::registration_json("tlsalice", "CorrectHorse7!");
            auto const request = "POST /_matrix/client/v3/register HTTP/1.1\r\nHost: localhost\r\nContent-Length: " +
                                 std::to_string(body.size()) + "\r\n\r\n" + body;
            REQUIRE(send_all_tls(*client_tls, request));
            auto tls_reader = TlsResponseReader{};
            auto const response = receive_tls_response(*client_tls, tls_reader);

            shutdown.fire();
            server_thread.join();
            // Joins the connection workers here, not during unwind: the client
            // sockets are already closed at this point so a parked worker sees
            // EOF and exits promptly, and if one ever does not, the failure
            // names this line instead of timing out the whole binary.
            pool.request_stop();

            THEN("the listener performs the TLS handshake and returns the Matrix JSON response")
            {
                REQUIRE(response.starts_with("HTTP/1.1 200"));
                REQUIRE(response.find(R"("user_id":"@tlsalice:example.org")") != std::string::npos);
                REQUIRE(stats.accepted_connections >= 1U);
                REQUIRE(stats.completed_requests >= 1U);
            }
        }
    }
}

SCENARIO("merovingian-server routes client listener traffic through the Matrix JSON adapter",
         "[homeserver][http][listener][client-server][integration]")
{
    GIVEN("a registration-enabled client-server runtime and a loopback HTTP listener")
    {
        auto const config = registration_enabled_config();
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto shutdown = merovingian::net::ShutdownSignal{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        // The pool is declared after the runtime so it is destroyed first.
        // ~ThreadPool joins the workers, and a worker can still be inside
        // serve_connection holding a ConnectionContext that references
        // `runtime` -- ASan caught exactly that read landing in this frame
        // after it had gone. Each WHEN block also stops the pool explicitly
        // (see below), so this ordering is the backstop rather than the only
        // thing standing between a worker and a destroyed runtime.
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{4U};

        WHEN("a client sends Matrix JSON registration over TCP")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_http(acceptor, runtime, shutdown, stats,
                                                    merovingian::homeserver::HttpDispatchMode::client_server, pool);
            }};

            auto const body = merovingian::tests::registration_json("alice", "CorrectHorse7!");
            // Connection: close keeps the read-until-close below valid now that
            // the listener defaults to HTTP/1.1 persistent connections.
            auto const request = "POST /_matrix/client/v3/register HTTP/1.1\r\nHost: localhost\r\nConnection: "
                                 "close\r\nContent-Length: " +
                                 std::to_string(body.size()) + "\r\n\r\n" + body;

            auto const client_fd = connect_loopback(port);
            REQUIRE(client_fd >= 0);
            REQUIRE(send_all(client_fd, request));
            auto const response = receive_until_close(client_fd);
            ::close(client_fd);

            shutdown.fire();
            server_thread.join();
            // Joins the connection workers here, not during unwind: the client
            // sockets are already closed at this point so a parked worker sees
            // EOF and exits promptly, and if one ever does not, the failure
            // names this line instead of timing out the whole binary.
            pool.request_stop();

            THEN("the listener returns the Matrix JSON registration response")
            {
                REQUIRE(response.starts_with("HTTP/1.1 200"));
                REQUIRE(response.find(R"("user_id":"@alice:example.org")") != std::string::npos);
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
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();

        auto shutdown = merovingian::net::ShutdownSignal{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        // The pool is declared after the runtime so it is destroyed first.
        // ~ThreadPool joins the workers, and a worker can still be inside
        // serve_connection holding a ConnectionContext that references
        // `runtime` -- ASan caught exactly that read landing in this frame
        // after it had gone. Each WHEN block also stops the pool explicitly
        // (see below), so this ordering is the backstop rather than the only
        // thing standing between a worker and a destroyed runtime.
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{4U};

        auto server_thread = std::thread{[&]() {
            merovingian::homeserver::serve_http(acceptor, runtime, shutdown, stats,
                                                merovingian::homeserver::HttpDispatchMode::client_server, pool);
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
            auto follow_reader = PlainResponseReader{};
            auto const follow_response = receive_response(follow_fd, follow_reader);
            ::close(follow_fd);

            shutdown.fire();
            server_thread.join();
            // Joins the connection workers here, not during unwind: the client
            // sockets are already closed at this point so a parked worker sees
            // EOF and exits promptly, and if one ever does not, the failure
            // names this line instead of timing out the whole binary.
            pool.request_stop();

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

SCENARIO("merovingian-server serves sequential requests over one persistent HTTP/1.1 connection",
         "[homeserver][http][listener][keep-alive][integration]")
{
    GIVEN("a started runtime and a TCP acceptor bound to an ephemeral loopback port")
    {
        auto const config = registration_enabled_config();
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto shutdown = merovingian::net::ShutdownSignal{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        // The pool is declared after the runtime so it is destroyed first.
        // ~ThreadPool joins the workers, and a worker can still be inside
        // serve_connection holding a ConnectionContext that references
        // `runtime` -- ASan caught exactly that read landing in this frame
        // after it had gone. Each WHEN block also stops the pool explicitly
        // (see below), so this ordering is the backstop rather than the only
        // thing standing between a worker and a destroyed runtime.
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{4U};

        WHEN("a client sends two sequential requests over the same connection")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_http(acceptor, runtime, shutdown, stats,
                                                    merovingian::homeserver::HttpDispatchMode::local_router, pool);
            }};

            auto const client_fd = connect_loopback(port);
            REQUIRE(client_fd >= 0);
            auto reader = PlainResponseReader{};

            auto const request = std::string{"GET /no-such-route HTTP/1.1\r\nHost: localhost\r\n\r\n"};
            REQUIRE(send_all(client_fd, request));
            auto const first_response = receive_response(client_fd, reader);

            // The connection is held open after the first response; the second
            // request must be served without a reconnect or a second accept.
            REQUIRE(send_all(client_fd, request));
            auto const second_response = receive_response(client_fd, reader);
            ::close(client_fd);

            shutdown.fire();
            server_thread.join();
            // Joins the connection workers here, not during unwind: the client
            // sockets are already closed at this point so a parked worker sees
            // EOF and exits promptly, and if one ever does not, the failure
            // names this line instead of timing out the whole binary.
            pool.request_stop();

            THEN("both responses are served over the single accepted connection")
            {
                REQUIRE(first_response.starts_with("HTTP/1.1 404"));
                REQUIRE(first_response.find("Connection: keep-alive") != std::string::npos);
                REQUIRE(first_response.find("Keep-Alive: timeout=") != std::string::npos);
                REQUIRE(second_response.starts_with("HTTP/1.1 404"));
                REQUIRE(stats.accepted_connections == 1U);
                REQUIRE(stats.completed_requests >= 2U);
            }
        }
    }
}

SCENARIO("merovingian-server drains a request body exactly before serving the next pipelined request",
         "[homeserver][http][listener][keep-alive][integration]")
{
    GIVEN("a started runtime and a TCP acceptor bound to an ephemeral loopback port")
    {
        auto const config = registration_enabled_config();
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto shutdown = merovingian::net::ShutdownSignal{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        // The pool is declared after the runtime so it is destroyed first.
        // ~ThreadPool joins the workers, and a worker can still be inside
        // serve_connection holding a ConnectionContext that references
        // `runtime` -- ASan caught exactly that read landing in this frame
        // after it had gone. Each WHEN block also stops the pool explicitly
        // (see below), so this ordering is the backstop rather than the only
        // thing standing between a worker and a destroyed runtime.
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{4U};

        WHEN("a client pipelines a POST body and a follow-up request in one write")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_http(acceptor, runtime, shutdown, stats,
                                                    merovingian::homeserver::HttpDispatchMode::local_router, pool);
            }};

            auto const client_fd = connect_loopback(port);
            REQUIRE(client_fd >= 0);

            auto const request =
                std::string{"POST /no-such-route HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\nHELLO"
                            "GET /also-no-route HTTP/1.1\r\nHost: localhost\r\n\r\n"};
            REQUIRE(send_all(client_fd, request));

            auto reader = PlainResponseReader{};
            auto const first_response = receive_response(client_fd, reader);
            auto const second_response = receive_response(client_fd, reader);
            ::close(client_fd);

            shutdown.fire();
            server_thread.join();
            // Joins the connection workers here, not during unwind: the client
            // sockets are already closed at this point so a parked worker sees
            // EOF and exits promptly, and if one ever does not, the failure
            // names this line instead of timing out the whole binary.
            pool.request_stop();

            THEN("the full body is drained and the follow-up request is served on the same connection")
            {
                REQUIRE(first_response.starts_with("HTTP/1.1 404"));
                REQUIRE(second_response.starts_with("HTTP/1.1 404"));
                REQUIRE(stats.accepted_connections == 1U);
                REQUIRE(stats.completed_requests >= 2U);
            }
        }
    }
}

SCENARIO("merovingian-server rate limits a route per IP, answers 429 on the kept-alive connection, then recovers",
         "[homeserver][http][listener][rate-limit][keep-alive][integration]")
{
    GIVEN("a runtime with a 2-requests-per-second cap on the versions endpoint and a loopback HTTP listener")
    {
        // A one-second window keeps the in-test recovery wait short while
        // still exercising the same wall-clock rollover the 60s defaults use.
        auto rate_limits = merovingian::config::ClientRateLimitsConfig{};
        rate_limits.per_ip["/_matrix/client/versions"] = {2U, 1U};
        auto security = merovingian::config::SecurityConfig{};
        // A runtime refuses to mint a signing secret it cannot encrypt at rest
        // (0.12.5 audit, finding 1), so every fixture needs a master key.
        security.secrets.master_key_file = merovingian::tests::shared_master_key_file();
        merovingian::tests::enable_token_registration(security);
        auto const config = merovingian::config::Config{
            merovingian::config::ServerConfig{},
            merovingian::config::ListenersConfig{},
            merovingian::config::DatabaseConfig{},
            security,
            std::move(rate_limits),
            merovingian::config::LogModulesConfig{},
        };
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto shutdown = merovingian::net::ShutdownSignal{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        // The pool is declared after the runtime so it is destroyed first.
        // ~ThreadPool joins the workers, and a worker can still be inside
        // serve_connection holding a ConnectionContext that references
        // `runtime` -- ASan caught exactly that read landing in this frame
        // after it had gone. Each WHEN block also stops the pool explicitly
        // (see below), so this ordering is the backstop rather than the only
        // thing standing between a worker and a destroyed runtime.
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{4U};

        WHEN("a client issues three requests over one persistent connection, waits out the window, then retries")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_http(acceptor, runtime, shutdown, stats,
                                                    merovingian::homeserver::HttpDispatchMode::client_server, pool);
            }};

            auto const client_fd = connect_loopback(port);
            REQUIRE(client_fd >= 0);
            auto reader = PlainResponseReader{};
            auto const request = std::string{"GET /_matrix/client/versions HTTP/1.1\r\nHost: localhost\r\n\r\n"};

            REQUIRE(send_all(client_fd, request));
            auto const first_response = receive_response(client_fd, reader);
            REQUIRE(send_all(client_fd, request));
            auto const second_response = receive_response(client_fd, reader);
            REQUIRE(send_all(client_fd, request));
            auto const throttled_response = receive_response(client_fd, reader);

            // The 429 must NOT tear down the keep-alive connection: the
            // framing decision is per request round and status-independent.
            REQUIRE(throttled_response.find("Connection: keep-alive") != std::string::npos);

            // The 1s window has rolled by the time this fires, so the next
            // round is served normally on the same connection.
            std::this_thread::sleep_for(std::chrono::milliseconds{1200});
            REQUIRE(send_all(client_fd, request));
            auto const recovered_response = receive_response(client_fd, reader);
            ::close(client_fd);

            shutdown.fire();
            server_thread.join();
            // Joins the connection workers here, not during unwind: the client
            // sockets are already closed at this point so a parked worker sees
            // EOF and exits promptly, and if one ever does not, the failure
            // names this line instead of timing out the whole binary.
            pool.request_stop();

            THEN("the third round is a 429 with the spec error shape and the fourth is served after the window")
            {
                REQUIRE(first_response.starts_with("HTTP/1.1 200"));
                REQUIRE(second_response.starts_with("HTTP/1.1 200"));
                REQUIRE(throttled_response.starts_with("HTTP/1.1 429"));
                REQUIRE(throttled_response.find("M_LIMIT_EXCEEDED") != std::string::npos);
                REQUIRE(throttled_response.find("retry_after_ms") != std::string::npos);
                REQUIRE(throttled_response.find("Retry-After:") != std::string::npos);
                REQUIRE(recovered_response.starts_with("HTTP/1.1 200"));
                // Everything above ran as request rounds on ONE accepted
                // connection: the 429 never forced a reconnect.
                REQUIRE(stats.accepted_connections == 1U);
                REQUIRE(stats.completed_requests >= 4U);
            }
        }
    }
}

SCENARIO("merovingian-server honours a client Connection close request and closes after the response",
         "[homeserver][http][listener][keep-alive][integration]")
{
    GIVEN("a started runtime and a TCP acceptor bound to an ephemeral loopback port")
    {
        auto const config = registration_enabled_config();
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto shutdown = merovingian::net::ShutdownSignal{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        // The pool is declared after the runtime so it is destroyed first.
        // ~ThreadPool joins the workers, and a worker can still be inside
        // serve_connection holding a ConnectionContext that references
        // `runtime` -- ASan caught exactly that read landing in this frame
        // after it had gone. Each WHEN block also stops the pool explicitly
        // (see below), so this ordering is the backstop rather than the only
        // thing standing between a worker and a destroyed runtime.
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{4U};

        WHEN("a client sends a request carrying Connection: close")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_http(acceptor, runtime, shutdown, stats,
                                                    merovingian::homeserver::HttpDispatchMode::local_router, pool);
            }};

            auto const client_fd = connect_loopback(port);
            REQUIRE(client_fd >= 0);
            REQUIRE(send_all(client_fd, "GET /no-such-route HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"));

            auto reader = PlainResponseReader{};
            auto const response = receive_response(client_fd, reader);
            auto const server_closed = peer_closed_within(client_fd, 5000);
            ::close(client_fd);

            shutdown.fire();
            server_thread.join();
            // Joins the connection workers here, not during unwind: the client
            // sockets are already closed at this point so a parked worker sees
            // EOF and exits promptly, and if one ever does not, the failure
            // names this line instead of timing out the whole binary.
            pool.request_stop();

            THEN("the response echoes Connection: close and the server closes the connection")
            {
                REQUIRE(response.starts_with("HTTP/1.1 404"));
                REQUIRE(response.find("Connection: close") != std::string::npos);
                REQUIRE(server_closed);
                REQUIRE(stats.completed_requests >= 1U);
            }
        }
    }
}

SCENARIO("merovingian-server closes a kept-alive connection after the configured idle window",
         "[homeserver][http][listener][keep-alive][integration]")
{
    GIVEN("a runtime configured with a one-second keep-alive idle window")
    {
        auto config = registration_enabled_config();
        config.server().http.keep_alive_idle_seconds = 1U;
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto shutdown = merovingian::net::ShutdownSignal{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        // The pool is declared after the runtime so it is destroyed first.
        // ~ThreadPool joins the workers, and a worker can still be inside
        // serve_connection holding a ConnectionContext that references
        // `runtime` -- ASan caught exactly that read landing in this frame
        // after it had gone. Each WHEN block also stops the pool explicitly
        // (see below), so this ordering is the backstop rather than the only
        // thing standing between a worker and a destroyed runtime.
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{4U};

        WHEN("a client sends one request and then goes idle on the kept-alive connection")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_http(acceptor, runtime, shutdown, stats,
                                                    merovingian::homeserver::HttpDispatchMode::local_router, pool);
            }};

            auto const client_fd = connect_loopback(port);
            REQUIRE(client_fd >= 0);
            REQUIRE(send_all(client_fd, "GET /no-such-route HTTP/1.1\r\nHost: localhost\r\n\r\n"));

            auto reader = PlainResponseReader{};
            auto const response = receive_response(client_fd, reader);
            // The server must close the idle connection within a bounded
            // window around the configured one-second idle timeout.
            auto const server_closed = peer_closed_within(client_fd, 5000);
            ::close(client_fd);

            shutdown.fire();
            server_thread.join();
            // Joins the connection workers here, not during unwind: the client
            // sockets are already closed at this point so a parked worker sees
            // EOF and exits promptly, and if one ever does not, the failure
            // names this line instead of timing out the whole binary.
            pool.request_stop();

            THEN("the response keeps the connection alive and the idle window closes it afterwards")
            {
                REQUIRE(response.starts_with("HTTP/1.1 404"));
                REQUIRE(response.find("Connection: keep-alive") != std::string::npos);
                REQUIRE(server_closed);
                REQUIRE(stats.accepted_connections == 1U);
                REQUIRE(stats.completed_requests >= 1U);
            }
        }
    }
}

SCENARIO("merovingian-server caps how many connections it holds open waiting for keep-alive requests",
         "[homeserver][http][listener][keep-alive][integration][security]")
{
    GIVEN("a runtime configured with a keep-alive cap of two connections")
    {
        auto config = registration_enabled_config();
        config.server().http.keep_alive_max_connections = 2U;
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto shutdown = merovingian::net::ShutdownSignal{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        // The pool is declared after the runtime so it is destroyed first.
        // ~ThreadPool joins the workers, and a worker can still be inside
        // serve_connection holding a ConnectionContext that references
        // `runtime` -- ASan caught exactly that read landing in this frame
        // after it had gone. Each WHEN block also stops the pool explicitly
        // (see below), so this ordering is the backstop rather than the only
        // thing standing between a worker and a destroyed runtime.
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{4U};

        WHEN("three clients each hold a connection open after their first request")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_http(acceptor, runtime, shutdown, stats,
                                                    merovingian::homeserver::HttpDispatchMode::local_router, pool);
            }};

            auto request = std::string{"GET /no-such-route HTTP/1.1\r\nHost: localhost\r\n\r\n"};

            auto const first_fd = connect_loopback(port);
            REQUIRE(first_fd >= 0);
            auto first_reader = PlainResponseReader{};
            REQUIRE(send_all(first_fd, request));
            auto const first_response = receive_response(first_fd, first_reader);
            // Give the server time to park the connection in the idle wait
            // before the next one is served, so the cap is observed exactly.
            std::this_thread::sleep_for(std::chrono::milliseconds{150});

            auto const second_fd = connect_loopback(port);
            REQUIRE(second_fd >= 0);
            auto second_reader = PlainResponseReader{};
            REQUIRE(send_all(second_fd, request));
            auto const second_response = receive_response(second_fd, second_reader);
            std::this_thread::sleep_for(std::chrono::milliseconds{150});

            auto const third_fd = connect_loopback(port);
            REQUIRE(third_fd >= 0);
            auto third_reader = PlainResponseReader{};
            REQUIRE(send_all(third_fd, request));
            auto const third_response = receive_response(third_fd, third_reader);

            ::close(first_fd);
            ::close(second_fd);
            ::close(third_fd);

            shutdown.fire();
            server_thread.join();
            // Joins the connection workers here, not during unwind: the client
            // sockets are already closed at this point so a parked worker sees
            // EOF and exits promptly, and if one ever does not, the failure
            // names this line instead of timing out the whole binary.
            pool.request_stop();

            THEN("the first two connections are kept alive and the third is closed instead of parked")
            {
                REQUIRE(first_response.find("Connection: keep-alive") != std::string::npos);
                REQUIRE(second_response.find("Connection: keep-alive") != std::string::npos);
                REQUIRE(third_response.find("Connection: close") != std::string::npos);
            }
        }
    }
}

SCENARIO("merovingian-server serves two sequential requests over one persistent TLS connection",
         "[homeserver][http][listener][tls][keep-alive][integration]")
{
    GIVEN("a TLS server context and a registration-enabled runtime")
    {
        auto const certificate = write_test_tls_certificate();
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());

        auto const config = registration_enabled_config();
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto shutdown = merovingian::net::ShutdownSignal{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        // The pool is declared after the runtime so it is destroyed first.
        // ~ThreadPool joins the workers, and a worker can still be inside
        // serve_connection holding a ConnectionContext that references
        // `runtime` -- ASan caught exactly that read landing in this frame
        // after it had gone. Each WHEN block also stops the pool explicitly
        // (see below), so this ordering is the backstop rather than the only
        // thing standing between a worker and a destroyed runtime.
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{4U};

        WHEN("a TLS client sends two sequential requests over the same TLS connection")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_tls_http(*tls_context.context, acceptor, runtime, shutdown, stats,
                                                        merovingian::homeserver::HttpDispatchMode::client_server, pool);
            }};

            auto client_context = std::unique_ptr<SSL_CTX, SslContextDeleter>{SSL_CTX_new(TLS_client_method())};
            REQUIRE(client_context != nullptr);
            SSL_CTX_set_verify(client_context.get(), SSL_VERIFY_NONE, nullptr);

            auto const client_fd = connect_loopback(port);
            REQUIRE(client_fd >= 0);
            auto client_socket = merovingian::core::SocketHandle{client_fd};
            auto client_tls = std::unique_ptr<SSL, SslDeleter>{SSL_new(client_context.get())};
            REQUIRE(client_tls != nullptr);
            REQUIRE(SSL_set_fd(client_tls.get(), client_socket.native_handle()) == 1);
            REQUIRE(SSL_connect(client_tls.get()) == 1);

            auto const request = std::string{"GET /no-such-route HTTP/1.1\r\nHost: localhost\r\n\r\n"};
            auto tls_reader = TlsResponseReader{};
            REQUIRE(send_all_tls(*client_tls, request));
            auto const first_response = receive_tls_response(*client_tls, tls_reader);

            // One TLS handshake must now serve both requests.
            REQUIRE(send_all_tls(*client_tls, request));
            auto const second_response = receive_tls_response(*client_tls, tls_reader);

            shutdown.fire();
            server_thread.join();
            // Joins the connection workers here, not during unwind: the client
            // sockets are already closed at this point so a parked worker sees
            // EOF and exits promptly, and if one ever does not, the failure
            // names this line instead of timing out the whole binary.
            pool.request_stop();

            THEN("both responses are served over the single accepted TLS connection")
            {
                // The client-server dispatcher authenticates before routing,
                // so an unauthenticated unknown route answers 401 — what is
                // under test here is the connection reuse, not the route.
                REQUIRE(first_response.starts_with("HTTP/1.1 401"));
                REQUIRE(first_response.find("Connection: keep-alive") != std::string::npos);
                REQUIRE(second_response.starts_with("HTTP/1.1 401"));
                REQUIRE(stats.accepted_connections == 1U);
                REQUIRE(stats.completed_requests >= 2U);
            }
        }
    }
}
