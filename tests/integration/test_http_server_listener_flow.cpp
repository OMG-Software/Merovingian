// SPDX-License-Identifier: GPL-3.0-or-later
#include "../support/in_memory_database_config.hpp"
#include "../support/master_key.hpp"
#include "../support/registration_token.hpp"
#include "../support/temp_directory.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/core/file_descriptor.hpp"
#include "merovingian/core/socket_handle.hpp"
#include "merovingian/homeserver/auth_service.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/http_server.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/net/shutdown_signal.hpp"
#include "merovingian/net/tcp_acceptor.hpp"
#include "merovingian/net/thread_pool.hpp"
#include "merovingian/sync/stream_token.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cerrno>
#include <charconv>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

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
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::tests::in_memory_database_config(),
        security,
        merovingian::config::ClientRateLimitsConfig{},
        merovingian::config::LogModulesConfig{},
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
// Finds the server-side fd for the still-open connection `client_fd` made:
// the socket whose local address is the client's peer and whose peer is the
// client's local address, both address and port. Matching the port alone
// found any socket in this process that happened to share it (a flake under
// parallel load). There is no production hook that exposes the accepted fd directly, so this
// scans the process's own fd table — reliable as long as the connection is
// still open when called, which the caller ensures by holding the request
// incomplete. Linux-only: relies on /proc/self/fd, which isn't guaranteed on
// the project's supported BSDs (see the SCENARIO below that uses this).
[[nodiscard]] auto find_accepted_socket_fd(int client_fd) -> int
{
    auto client_local = sockaddr_in{};
    auto client_local_len = socklen_t{sizeof(client_local)};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (::getsockname(client_fd, reinterpret_cast<sockaddr*>(&client_local), &client_local_len) != 0)
    {
        return -1;
    }
    auto client_peer = sockaddr_in{};
    auto client_peer_len = socklen_t{sizeof(client_peer)};
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (::getpeername(client_fd, reinterpret_cast<sockaddr*>(&client_peer), &client_peer_len) != 0)
    {
        return -1;
    }
    auto const same_endpoint = [](sockaddr_in const& lhs, sockaddr_in const& rhs) {
        return lhs.sin_family == AF_INET && rhs.sin_family == AF_INET && lhs.sin_port == rhs.sin_port &&
               lhs.sin_addr.s_addr == rhs.sin_addr.s_addr;
    };
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
        auto local = sockaddr_in{};
        auto local_len = socklen_t{sizeof(local)};
        auto peer = sockaddr_in{};
        auto peer_len = socklen_t{sizeof(peer)};
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
        if (::getsockname(candidate, reinterpret_cast<sockaddr*>(&local), &local_len) != 0 ||
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            ::getpeername(candidate, reinterpret_cast<sockaddr*>(&peer), &peer_len) != 0)
        {
            continue;
        }
        if (same_endpoint(local, client_peer) && same_endpoint(peer, client_local))
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
    // Bounded: a server that neither answers nor closes would otherwise block
    // here until meson kills the whole binary, hiding which scenario stalled
    // (OpenBSD CI: the integration binary hit its 900 s limit mid-scenario).
    // A stall now surfaces as an empty or partial response in that scenario.
    auto timeout = timeval{};
    timeout.tv_sec = 30;
    std::ignore = ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
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

// True once the peer has hung up. Any pending bytes are drained and discarded
// first: when the server answers a request the client then abandons, the socket
// becomes readable with RESPONSE DATA, which is not EOF. peer_closed_within()
// reports that case as "not closed" and returns immediately, so using it to pace
// a loop turns the loop into a busy spin — which is exactly how the trickle
// scenario below came to send thousands of bytes on NetBSD instead of one every
// 1.5 seconds.
[[nodiscard]] auto peer_closed_now(int fd) -> bool
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
            // Nothing pending is the connection still being open; anything else
            // (ECONNRESET, EPIPE) means the peer is gone.
            return errno != EAGAIN && errno != EWOULDBLOCK;
        }
        // Drained some response bytes; keep going until the socket is drained
        // so the EOF underneath them is visible.
    }
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

            // Held open across the connect and the accept, then freed so the
            // lookalike socket below lands on an fd number below the accepted
            // one and the fd-table scan meets it first.
            auto low_fd_reservation = merovingian::core::FileDescriptor{::open("/dev/null", O_RDONLY | O_CLOEXEC)};
            REQUIRE(low_fd_reservation.valid());

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
                accepted_fd = find_accepted_socket_fd(client_fd);
                if (accepted_fd < 0)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds{5});
                }
            }
            REQUIRE(accepted_fd >= 0);

            // A lookalike: another socket in this process, not close-on-exec,
            // whose peer port equals the client's local port but on another
            // loopback address. Under a parallel run any socket can look like
            // this; a scan that matched on the peer port alone picked it up.
            auto lookalike_listener =
                merovingian::core::FileDescriptor{::socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0)};
            REQUIRE(lookalike_listener.valid());
            auto lookalike_address = sockaddr_in{};
            lookalike_address.sin_family = AF_INET;
            lookalike_address.sin_port = htons(client_local_port);
            REQUIRE(::inet_pton(AF_INET, "127.0.0.2", &lookalike_address.sin_addr) == 1);
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            REQUIRE(::bind(lookalike_listener.get(), reinterpret_cast<sockaddr const*>(&lookalike_address),
                           sizeof(lookalike_address)) == 0);
            REQUIRE(::listen(lookalike_listener.get(), 1) == 0);
            low_fd_reservation.reset();
            auto lookalike = merovingian::core::FileDescriptor{::socket(AF_INET, SOCK_STREAM, 0)};
            REQUIRE(lookalike.valid());
            REQUIRE(lookalike.get() < accepted_fd);
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            REQUIRE(::connect(lookalike.get(), reinterpret_cast<sockaddr const*>(&lookalike_address),
                              sizeof(lookalike_address)) == 0);

            accepted_fd = find_accepted_socket_fd(client_fd);
            REQUIRE(accepted_fd >= 0);

            auto found_local = sockaddr_in{};
            auto found_local_len = socklen_t{sizeof(found_local)};
            auto found_peer = sockaddr_in{};
            auto found_peer_len = socklen_t{sizeof(found_peer)};
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            REQUIRE(::getsockname(accepted_fd, reinterpret_cast<sockaddr*>(&found_local), &found_local_len) == 0);
            // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
            REQUIRE(::getpeername(accepted_fd, reinterpret_cast<sockaddr*>(&found_peer), &found_peer_len) == 0);

            auto const flags = ::fcntl(accepted_fd, F_GETFD, 0);
            REQUIRE(flags >= 0);

            // Complete the request so the server thread can finish and be
            // joined cleanly by server_thread_guard's destructor below.
            REQUIRE(send_all(client_fd, "\r\n"));
            auto reader = PlainResponseReader{};
            std::ignore = receive_response(client_fd, reader);
            ::close(client_fd);

            THEN("the socket inspected is the server's end of the client's connection")
            {
                REQUIRE(ntohs(found_local.sin_port) == port);
                REQUIRE(found_local.sin_addr.s_addr == client_local.sin_addr.s_addr);
                REQUIRE(ntohs(found_peer.sin_port) == client_local_port);
                REQUIRE(found_peer.sin_addr.s_addr == client_local.sin_addr.s_addr);
            }

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

SCENARIO("merovingian-server keeps accepted plain-HTTP sockets non-blocking",
         "[homeserver][http][listener][integration][security]")
{
    GIVEN("a started runtime and a plain-HTTP acceptor bound to an ephemeral loopback port")
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
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{4U};

        WHEN("a client connects and holds the connection open with an incomplete request")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_http(acceptor, runtime, shutdown, stats,
                                                    merovingian::homeserver::HttpDispatchMode::local_router, pool);
            }};
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

            REQUIRE(send_all(client_fd, "GET /no-such-route HTTP/1.1\r\nHost: localhost\r\n"));

            auto accepted_fd = -1;
            for (auto attempt = 0; attempt < 200 && accepted_fd < 0; ++attempt)
            {
                accepted_fd = find_accepted_socket_fd(client_fd);
                if (accepted_fd < 0)
                {
                    std::this_thread::sleep_for(std::chrono::milliseconds{5});
                }
            }
            REQUIRE(accepted_fd >= 0);

            auto const status_flags = ::fcntl(accepted_fd, F_GETFL, 0);
            REQUIRE(status_flags >= 0);

            REQUIRE(send_all(client_fd, "\r\n"));
            auto reader = PlainResponseReader{};
            std::ignore = receive_response(client_fd, reader);
            ::close(client_fd);

            THEN("the accepted socket carries O_NONBLOCK for the life of the connection")
            {
                // ADR-0054 set the rule for TLS sockets: "no code below the
                // HTTP layer may perform a blocking I/O call on a connection
                // descriptor", because every timeout in the HTTP layer is
                // expressed as poll() on the descriptor and that is only a
                // timeout if the call beneath it cannot block. Plain-HTTP
                // sockets were left blocking, and while reads are guarded by
                // poll(POLLIN) the response write was not: a peer that stops
                // reading parked a worker inside ::send() indefinitely, with
                // no deadline anywhere above it. The flag is the invariant —
                // if it is ever cleared, send_all() can block forever again.
                REQUIRE((status_flags & O_NONBLOCK) != 0);
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

// M-03 (security audit 2026-09). Spec v1.19 §10.5 requires the client-server
// API to "supply Cross-Origin Resource Sharing (CORS) headers on all requests".
// Errors answered by the transport layer — before routing, and in the parser
// error case before there is even a parsed head — were the exception: a browser
// received them as an opaque CORS failure rather than the real status, so a
// client could not tell a 400 from a 413 from a network outage.
SCENARIO("merovingian-server puts CORS headers on transport-layer error responses",
         "[homeserver][http][listener][client-server][cors][integration]")
{
    GIVEN("a client-server listener with the default wildcard CORS allow-list")
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
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{4U};

        WHEN("a browser-shaped request with an unparseable request line arrives")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_http(acceptor, runtime, shutdown, stats,
                                                    merovingian::homeserver::HttpDispatchMode::client_server, pool);
            }};

            auto const client_fd = connect_loopback(port);
            REQUIRE(client_fd >= 0);
            REQUIRE(send_all(client_fd, "NOT-A-REQUEST-LINE\r\nOrigin: https://app.example.com\r\n\r\n"));
            auto const response = receive_until_close(client_fd);
            ::close(client_fd);

            shutdown.fire();
            server_thread.join();
            pool.request_stop();

            THEN("the parser error still carries Access-Control-Allow-Origin")
            {
                REQUIRE(response.starts_with("HTTP/1.1 4"));
                REQUIRE(response.find("Access-Control-Allow-Origin: *") != std::string::npos);
            }
        }

        WHEN("a browser-shaped request head exceeds the head cap")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_http(acceptor, runtime, shutdown, stats,
                                                    merovingian::homeserver::HttpDispatchMode::client_server, pool);
            }};

            auto const client_fd = connect_loopback(port);
            REQUIRE(client_fd >= 0);
            auto oversized =
                std::string{"GET /_matrix/client/versions HTTP/1.1\r\nOrigin: https://app.example.com\r\n"};
            // Never terminated: the head grows past the cap and the server
            // answers 413 without ever parsing a complete head.
            oversized.append("X-Filler: ");
            oversized.append(std::string(200000U, 'a'));
            oversized.append("\r\n");
            std::ignore = send_all(client_fd, oversized);
            auto const response = receive_until_close(client_fd);
            ::close(client_fd);

            shutdown.fire();
            server_thread.join();
            pool.request_stop();

            THEN("the head-too-large rejection also carries Access-Control-Allow-Origin")
            {
                REQUIRE(response.starts_with("HTTP/1.1 413"));
                REQUIRE(response.find("Access-Control-Allow-Origin: *") != std::string::npos);
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
            merovingian::tests::in_memory_database_config(),
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

// --- M-06 / M-07: bounded reads -------------------------------------------
//
// These two findings are one defect surface and are tested together. The HTTP
// layer expresses every timeout as poll() on the connection descriptor, and
// that is only a timeout if nothing beneath it can block:
//
//   M-06  read_remaining_body() enforced no overall deadline and no minimum
//         progress rate - only a fresh 15s poll per 4096-byte chunk - so a
//         client dribbling a declared Content-Length held a worker thread for
//         as long as it cared to. read_request_head() already enforced both
//         caps; the body did not.
//
//   M-07  TLS sockets were restored to blocking mode after the handshake, so
//         SSL_read could block indefinitely on a record the peer never
//         finished sending - past every deadline above it, because poll(POLLIN)
//         proves TCP bytes arrived, not that a whole TLS record did.
//
// A body deadline is inert on a TLS listener while a single read beneath it can
// block forever, which is why neither is fixed alone.

// M-06: the client stops sending part-way through a declared body. The worker
// must not stay parked on it. Pre-fix the only thing that eventually released
// the worker was the 15s per-read poll; the inter-byte cap now closes it at 5s,
// so the 10s bound below distinguishes the two.
SCENARIO("merovingian-server drops a client that stalls part-way through a request body",
         "[homeserver][http][listener][integration][security][m06]")
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
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{4U};

        auto server_thread = std::thread{[&]() {
            merovingian::homeserver::serve_http(acceptor, runtime, shutdown, stats,
                                                merovingian::homeserver::HttpDispatchMode::client_server, pool);
        }};

        WHEN("the client announces a body, sends a few bytes of it, and then goes silent")
        {
            auto const client_fd = connect_loopback(port);
            REQUIRE(client_fd >= 0);
            auto const head = std::string{"POST /_matrix/client/v3/register HTTP/1.1\r\nHost: localhost\r\n"
                                          "Content-Type: application/json\r\nContent-Length: 512\r\n\r\n"};
            REQUIRE(send_all(client_fd, head));
            // A partial body, then nothing at all.
            REQUIRE(send_all(client_fd, std::string{R"({"auth")"}));

            // Read until the server hangs up. peer_closed_within() is no use
            // here: the server answers the abandoned request before closing, so
            // the socket becomes readable with response bytes rather than EOF.
            // What is being measured is when the connection ends, because that
            // is when the worker goes back to the pool.
            auto const started = std::chrono::steady_clock::now();
            auto const response = receive_until_close(client_fd);
            auto const elapsed_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started)
                    .count();
            ::close(client_fd);

            // The listener must still be serving: the point of a deadline is
            // that the worker is returned to the pool, not merely that one
            // connection died.
            auto const follow_fd = connect_loopback(port);
            REQUIRE(follow_fd >= 0);
            REQUIRE(send_all(follow_fd, "GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"));
            auto follow_reader = PlainResponseReader{};
            auto const follow_response = receive_response(follow_fd, follow_reader);
            ::close(follow_fd);

            shutdown.fire();
            server_thread.join();
            pool.request_stop();

            THEN("the connection is closed well inside the old per-read window, and the listener keeps serving")
            {
                // Post-fix this is the 5s inter-byte cap firing. The old
                // behaviour could not release the connection before the 15s
                // per-read poll expired, so the bound has to sit between the
                // two to mean anything.
                //
                // Unlike the trickle scenario's deadline bound, this one CANNOT
                // simply be made generous: widening it past the 15s per-read
                // poll would make it pass against the unfixed code, which is the
                // one thing it exists to catch. 12s leaves better than 2x
                // headroom over the expected 5s while staying 3s clear of the
                // old floor. If a loaded runner ever pushes past it, the fix is
                // to make inter_byte_timeout injectable so the test can use a
                // short value and a proportionate bound — not to widen this
                // number toward 15s, which would quietly retire the assertion.
                REQUIRE(elapsed_ms < 12000);
                // Whether the server answers first or just hangs up, it must not
                // still be holding the request open.
                std::ignore = response;
                REQUIRE_FALSE(follow_response.empty());
                REQUIRE(follow_response.starts_with("HTTP/1.1 "));
            }
        }
    }
}

// M-06: the case the inter-byte cap alone does NOT catch, and the reason the
// finding asks for a total deadline as well as a progress rate. This client
// never goes silent for long enough to trip the inter-byte cap - it trickles
// steadily, just slowly. Without an overall deadline the read loop follows it
// for as long as it keeps trickling, which for the Content-Length below is
// hours. This is the scenario that actually covers the new deadline, so it is
// worth the wall-clock time it costs.
SCENARIO("sync admission bounds one account across devices without holding the request worker",
         "[http-4][sync][admission]")
{
    GIVEN("two accounts and a live 32-thread sync pool")
    {
        auto started = merovingian::homeserver::start_client_server(registration_enabled_config());
        REQUIRE(started.started);
        auto runtime = std::move(started.runtime);
        runtime.rate_limit_engine.reset(); // Isolate concurrent admission from rate counters.
        auto const alice = merovingian::homeserver::register_local_user(
            runtime.homeserver, "poll_alice", "CorrectHorse7!", merovingian::tests::registration_token);
        auto const bob = merovingian::homeserver::register_local_user(runtime.homeserver, "poll_bob", "CorrectHorse7!",
                                                                      merovingian::tests::registration_token);
        REQUIRE(alice.ok);
        REQUIRE(bob.ok);
        auto tokens = std::vector<std::string>{};
        for (auto device = 0U; device < 5U; ++device)
        {
            auto const login = merovingian::homeserver::login_local_user_by_id(runtime.homeserver, alice.value,
                                                                               "DEVICE" + std::to_string(device));
            REQUIRE(login.ok);
            tokens.push_back(login.value);
        }
        auto const bob_login = merovingian::homeserver::login_local_user_by_id(runtime.homeserver, bob.value, "BOB");
        REQUIRE(bob_login.ok);
        auto const since =
            merovingian::sync::encode_stream_token({runtime.homeserver.database.next_stream_ordering - 1U, 0U,
                                                    runtime.homeserver.database.persistent_store.next_sync_stream_id});
        auto pool = merovingian::net::ThreadPool{32U};
        auto stats = merovingian::homeserver::HttpServeStats{};
        auto clients = std::vector<merovingian::core::FileDescriptor>{};
        auto refused = std::vector<std::string>{};
        auto poll_count = std::size_t{0U};
        auto const request_poll = [&](std::string const& token) {
            auto sockets = std::array<int, 2>{-1, -1};
            REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets.data()) == 0);
            auto server = merovingian::core::FileDescriptor{sockets[0]};
            auto client = merovingian::core::FileDescriptor{sockets[1]};
            auto const sliding = (poll_count++ % 2U) != 0U;
            auto const request =
                (sliding ? "POST /_matrix/client/unstable/org.matrix.simplified_msc3575/sync?pos="
                         : "GET /_matrix/client/v3/sync?since=") +
                since + "&timeout=1500 HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + token +
                (sliding ? "\r\nConnection: close\r\nContent-Length: 2\r\n\r\n{}" : "\r\nConnection: close\r\n\r\n");
            REQUIRE(send_all(client.get(), request));
            auto const transferred = merovingian::homeserver::serve_one_http_connection(
                server.get(), runtime, stats, merovingian::homeserver::HttpDispatchMode::client_server, &pool);
            if (transferred)
            {
                std::ignore = server.release();
                clients.push_back(std::move(client));
            }
            else
            {
                server.reset();
                refused.push_back(receive_until_close(client.get()));
            }
            return transferred;
        };

        WHEN("one device opens three mixed-protocol polls and the account attempts forty across five devices")
        {
            CHECK(request_poll(tokens[0]));
            CHECK(request_poll(tokens[0]));
            auto const device_overflow = request_poll(tokens[0]);
            for (auto i = 3U; i < 40U; ++i)
            {
                std::ignore = request_poll(tokens[i % tokens.size()]);
            }
            auto const alice_admitted = clients.size();
            auto const bob_admitted = request_poll(bob_login.value);
            clients.clear(); // Disconnect every admitted poll before stopping the pool.
            pool.request_stop();

            THEN("the device has two slots, the account has four, and another account is admitted")
            {
                CHECK_FALSE(device_overflow);
                CHECK(alice_admitted == 4U);
                CHECK(bob_admitted);
                CHECK(runtime.sync_user_budget->active() == 0U);
                CHECK(runtime.sync_device_budget->active() == 0U);
                REQUIRE(refused.size() == 36U);
                for (auto const& response : refused)
                {
                    CHECK(response.starts_with("HTTP/1.1 429"));
                    CHECK(response.find("M_LIMIT_EXCEEDED") != std::string::npos);
                    CHECK(response.find("retry_after_ms") != std::string::npos);
                }
            }
        }
        WHEN("the sync pool refuses a handoff")
        {
            pool.request_stop();
            auto const began = std::chrono::steady_clock::now();
            auto const transferred = request_poll(tokens[0]);
            auto const elapsed = std::chrono::steady_clock::now() - began;
            THEN("the request gets immediate backpressure and both admission slots are released")
            {
                CHECK_FALSE(transferred);
                CHECK(elapsed < std::chrono::milliseconds{500});
                REQUIRE(refused.size() == 1U);
                CHECK(refused.front().starts_with("HTTP/1.1 429"));
                CHECK(runtime.sync_user_budget->active() == 0U);
                CHECK(runtime.sync_device_budget->active() == 0U);
            }
        }
    }
}

// A long-poll /sync that waits is run again after every wake-up and once more
// when its timeout expires: on the sync pool, in the no-pool fallback and in
// dispatch_local_http_request. Each re-run used to go through the rate limiter
// again, so a client allowed exactly one more /sync had its waiting request
// refused with 429 when it was finally answered (ADR-0121 rate_limit_admitted).
SCENARIO("A waiting sync is counted against the rate limit once, however often it is run again",
         "[http-4][sync][rate-limit]")
{
    GIVEN("a sync rate limit of one request per minute and a logged-in device")
    {
        auto config = registration_enabled_config();
        config.client_rate_limits().tier["sync"] = merovingian::http::RateLimitPolicy{1U, 60U};
        auto started = merovingian::homeserver::start_client_server(config);
        REQUIRE(started.started);
        auto& runtime = started.runtime;
        auto const alice = merovingian::homeserver::register_local_user(
            runtime.homeserver, "limited_poller", "CorrectHorse7!", merovingian::tests::registration_token);
        REQUIRE(alice.ok);
        auto const login = merovingian::homeserver::login_local_user_by_id(runtime.homeserver, alice.value, "POLL");
        REQUIRE(login.ok);
        auto const since =
            merovingian::sync::encode_stream_token({runtime.homeserver.database.next_stream_ordering - 1U, 0U,
                                                    runtime.homeserver.database.persistent_store.next_sync_stream_id});
        auto const sync_target = [&since](std::string_view timeout_ms) {
            return "/_matrix/client/v3/sync?since=" + since + "&timeout=" + std::string{timeout_ms};
        };
        auto stats = merovingian::homeserver::HttpServeStats{};
        // Serves one request on a socketpair, as a request-pool worker does, and
        // returns the response once the server has closed the connection.
        auto const serve_on_socket = [&](std::string const& target,
                                         merovingian::net::ThreadPool* sync_pool) -> std::pair<bool, std::string> {
            auto sockets = std::array<int, 2>{-1, -1};
            REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets.data()) == 0);
            auto server = merovingian::core::FileDescriptor{sockets[0]};
            auto client = merovingian::core::FileDescriptor{sockets[1]};
            REQUIRE(send_all(client.get(), "GET " + target + " HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " +
                                               login.value + "\r\nConnection: close\r\n\r\n"));
            auto const transferred = merovingian::homeserver::serve_one_http_connection(
                server.get(), runtime, stats, merovingian::homeserver::HttpDispatchMode::client_server, sync_pool);
            if (transferred)
            {
                std::ignore = server.release();
            }
            else
            {
                server.reset();
            }
            return {transferred, receive_until_close(client.get())};
        };

        WHEN("a long-poll waits on the sync pool until its timeout and is answered")
        {
            auto pool = merovingian::net::ThreadPool{4U};
            auto const [transferred, response] = serve_on_socket(sync_target("300"), &pool);
            auto const [next_transferred, next_response] = serve_on_socket(sync_target("0"), &pool);
            pool.request_stop();

            THEN("the waiting sync is answered, not refused as a second request")
            {
                REQUIRE(transferred);
                INFO(response.substr(0U, 200U));
                REQUIRE(response.starts_with("HTTP/1.1 200"));
            }

            THEN("the limit still refuses the client's next sync in the window")
            {
                REQUIRE_FALSE(next_transferred);
                REQUIRE(next_response.starts_with("HTTP/1.1 429"));
            }
        }

        WHEN("a long-poll on the sync pool is woken by a new event and run again")
        {
            auto pool = merovingian::net::ThreadPool{4U};
            // Built and checked on this thread: Catch2 assertions are not
            // thread-safe, so the poller thread only serves the request.
            auto sockets = std::array<int, 2>{-1, -1};
            REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets.data()) == 0);
            auto server = merovingian::core::FileDescriptor{sockets[0]};
            auto client = merovingian::core::FileDescriptor{sockets[1]};
            REQUIRE(send_all(client.get(), "GET " + sync_target("10000") +
                                               " HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + login.value +
                                               "\r\nConnection: close\r\n\r\n"));
            auto transferred = false;
            auto poller = std::thread{[&] {
                transferred = merovingian::homeserver::serve_one_http_connection(
                    server.get(), runtime, stats, merovingian::homeserver::HttpDispatchMode::client_server, &pool);
            }};
            poller.join();
            if (transferred)
            {
                std::ignore = server.release();
            }
            // The long-poll is waiting once its admission slot is held.
            auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
            while (runtime.sync_user_budget->active() == 0U && std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds{5});
            }
            auto const began_waiting = runtime.sync_user_budget->active() == 1U;
            auto const created = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", login.value, "{}"});
            auto const response = receive_until_close(client.get());
            pool.request_stop();

            THEN("the woken sync is answered with the new room, not refused as a second request")
            {
                REQUIRE(transferred);
                REQUIRE(began_waiting);
                REQUIRE(created.response.status == 200U);
                INFO(response.substr(0U, 200U));
                REQUIRE(response.starts_with("HTTP/1.1 200"));
                REQUIRE(response.find("\"join\"") != std::string::npos);
            }
        }

        // Waits until a long-poll is blocked in the notifier, then creates a
        // room for the device so the waiting sync is woken and run again.
        auto const wake_waiting_sync = [&runtime, &login] {
            auto const deadline = std::chrono::steady_clock::now() + std::chrono::seconds{10};
            while (runtime.sync_notifier->waiting() == 0U && std::chrono::steady_clock::now() < deadline)
            {
                std::this_thread::sleep_for(std::chrono::milliseconds{5});
            }
            auto const was_waiting = runtime.sync_notifier->waiting() == 1U;
            auto const created = merovingian::homeserver::handle_client_server_request(
                runtime, {"POST", "/_matrix/client/v3/createRoom", login.value, "{}"});
            return was_waiting && created.response.status == 200U;
        };

        WHEN("a long-poll waits on its request worker, with no sync pool, until its timeout")
        {
            auto const [transferred, response] = serve_on_socket(sync_target("300"), nullptr);

            THEN("it is answered on that worker, not refused as a second request")
            {
                REQUIRE_FALSE(transferred);
                INFO(response.substr(0U, 200U));
                REQUIRE(response.starts_with("HTTP/1.1 200"));
            }
        }

        WHEN("a long-poll waiting on its request worker, with no sync pool, is woken by a new event")
        {
            // Built and checked on this thread: Catch2 assertions are not
            // thread-safe, so the worker thread only serves the request.
            auto sockets = std::array<int, 2>{-1, -1};
            REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sockets.data()) == 0);
            auto server = merovingian::core::FileDescriptor{sockets[0]};
            auto client = merovingian::core::FileDescriptor{sockets[1]};
            REQUIRE(send_all(client.get(), "GET " + sync_target("10000") +
                                               " HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer " + login.value +
                                               "\r\nConnection: close\r\n\r\n"));
            auto transferred = true;
            auto worker = std::thread{[&] {
                transferred = merovingian::homeserver::serve_one_http_connection(
                    server.get(), runtime, stats, merovingian::homeserver::HttpDispatchMode::client_server, nullptr);
            }};
            auto const woken = wake_waiting_sync();
            worker.join();
            server.reset();
            auto const response = receive_until_close(client.get());

            THEN("the woken sync is answered with the new room, not refused as a second request")
            {
                REQUIRE(woken);
                REQUIRE_FALSE(transferred);
                INFO(response.substr(0U, 200U));
                REQUIRE(response.starts_with("HTTP/1.1 200"));
                REQUIRE(response.find("\"join\"") != std::string::npos);
            }
        }

        WHEN("a long-poll waiting in dispatch_local_http_request is woken by a new event")
        {
            auto response = merovingian::homeserver::LocalHttpResponse{};
            auto waiter = std::thread{[&] {
                response = merovingian::homeserver::dispatch_local_http_request(
                    runtime, {"GET", sync_target("10000"), login.value, {}},
                    merovingian::homeserver::HttpDispatchMode::client_server);
            }};
            auto const woken = wake_waiting_sync();
            waiter.join();

            THEN("the woken sync is answered with the new room, not refused as a second request")
            {
                REQUIRE(woken);
                INFO(response.body.substr(0U, 200U));
                REQUIRE(response.status == 200U);
                REQUIRE(response.body.find("\"join\"") != std::string::npos);
            }
        }

        WHEN("a long-poll waits in dispatch_local_http_request, which has no sync pool")
        {
            auto const response = merovingian::homeserver::dispatch_local_http_request(
                runtime, {"GET", sync_target("300"), login.value, {}},
                merovingian::homeserver::HttpDispatchMode::client_server);

            THEN("it is answered, not refused as a second request")
            {
                INFO(response.body.substr(0U, 200U));
                REQUIRE(response.status == 200U);
            }
        }
    }
}

SCENARIO("merovingian-server bounds a client that trickles a body indefinitely under the inter-byte cap",
         "[homeserver][http][listener][integration][security][m06][slow]")
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
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{4U};

        auto server_thread = std::thread{[&]() {
            merovingian::homeserver::serve_http(acceptor, runtime, shutdown, stats,
                                                merovingian::homeserver::HttpDispatchMode::client_server, pool);
        }};

        WHEN("the client sends one byte at a time, always inside the inter-byte cap")
        {
            auto const client_fd = connect_loopback(port);
            REQUIRE(client_fd >= 0);
            // 4096 bytes at one byte per 1.5s is over 100 minutes of dribbling
            // if nothing bounds it.
            auto const head = std::string{"POST /_matrix/client/v3/register HTTP/1.1\r\nHost: localhost\r\n"
                                          "Content-Type: application/json\r\nContent-Length: 4096\r\n\r\n"};
            REQUIRE(send_all(client_fd, head));

            auto const started = std::chrono::steady_clock::now();
            auto bytes_sent = std::size_t{0U};
            auto closed = false;
            // What this scenario distinguishes is BOUNDED from UNBOUNDED, not
            // one duration from another: without the overall deadline this
            // client is followed until it finishes, which at one byte per 1.5s
            // is over 100 minutes. So the bound can be enormously generous and
            // still mean exactly what it is meant to mean, and generous is what
            // it should be — a loaded CI runner adds scheduling delay on both
            // sides of a ~30s wait, and a bound tuned close to the expected
            // value buys nothing and flakes.
            //
            // give_up must stay ABOVE deadline_bound so that exceeding the
            // bound is reported as a bound breach with a real elapsed time,
            // rather than as the loop quietly running out first.
            auto constexpr deadline_bound = std::chrono::milliseconds{120000};
            auto constexpr give_up = std::chrono::seconds{150};
            // Pace the dribble with an explicit sleep rather than with a poll
            // timeout. Once the server answers, a poll returns instantly on the
            // response bytes, and a loop paced by it stops dribbling and starts
            // spinning — the cadence has to be independent of readability.
            auto constexpr dribble_interval = std::chrono::milliseconds{1500};
            while (std::chrono::steady_clock::now() - started < give_up)
            {
                std::this_thread::sleep_for(dribble_interval);
                if (peer_closed_now(client_fd))
                {
                    closed = true;
                    break;
                }
                if (!send_all(client_fd, std::string{"x"}))
                {
                    // The server closed and the write failed: also a close.
                    closed = true;
                    break;
                }
                ++bytes_sent;
            }
            auto const elapsed_ms =
                std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started)
                    .count();
            ::close(client_fd);

            shutdown.fire();
            server_thread.join();
            pool.request_stop();

            THEN("the overall body deadline ends the request even though every gap was a legal one")
            {
                REQUIRE(closed);
                // The deadline is the 30s base plus the declared length at the
                // 16 KiB/s floor, so ~30s is expected. Anything inside the
                // two-minute bound is the deadline firing; without it this
                // client is followed for over 100 minutes.
                REQUIRE(elapsed_ms < deadline_bound.count());
                // And it was cut off mid-body, not allowed to finish. At one
                // byte per 1.5s the declared 4096 cannot be reached inside the
                // give-up window even if nothing bounds the request, so this is
                // a sanity check on the dribble rate rather than a second
                // measure of the deadline.
                REQUIRE(bytes_sent < 4096U);
            }
        }
    }
}

// M-06: the deadline scales with the declared length at a deliberately low
// throughput floor so that a genuinely slow-but-steady upload is never cut off.
// A fix that bounded the body by a flat timeout would pass the two scenarios
// above and break real clients; this is the scenario that would catch it.
SCENARIO("merovingian-server accepts a body delivered slowly but steadily",
         "[homeserver][http][listener][integration][m06]")
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
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{4U};

        auto server_thread = std::thread{[&]() {
            merovingian::homeserver::serve_http(acceptor, runtime, shutdown, stats,
                                                merovingian::homeserver::HttpDispatchMode::client_server, pool);
        }};

        WHEN("the client sends a sizeable body in chunks with real gaps between them")
        {
            auto constexpr chunk_count = std::size_t{6U};
            auto constexpr chunk_bytes = std::size_t{8192U};
            auto const total = chunk_count * chunk_bytes;

            auto const client_fd = connect_loopback(port);
            REQUIRE(client_fd >= 0);
            auto const head = std::string{"POST /_matrix/client/v3/register HTTP/1.1\r\nHost: localhost\r\n"
                                          "Content-Type: application/json\r\nContent-Length: "} +
                              std::to_string(total) + "\r\n\r\n";
            REQUIRE(send_all(client_fd, head));

            auto sent_every_chunk = true;
            for (auto chunk = std::size_t{0U}; chunk < chunk_count; ++chunk)
            {
                // 800ms between chunks: comfortably inside the inter-byte cap,
                // and slow enough that a flat short deadline would reject it.
                std::this_thread::sleep_for(std::chrono::milliseconds{800});
                if (!send_all(client_fd, std::string(chunk_bytes, 'x')))
                {
                    sent_every_chunk = false;
                    break;
                }
            }
            auto reader = PlainResponseReader{};
            auto const response = receive_response(client_fd, reader);
            ::close(client_fd);

            shutdown.fire();
            server_thread.join();
            pool.request_stop();

            THEN("the whole body is read and the request is answered rather than dropped")
            {
                REQUIRE(sent_every_chunk);
                // The body is deliberate junk, so the status is a client error.
                // What matters is that the server read all of it and replied,
                // instead of timing the connection out part-way through.
                REQUIRE_FALSE(response.empty());
                REQUIRE(response.starts_with("HTTP/1.1 "));
            }
        }
    }
}

// M-07: a peer that opens a TLS record and never finishes it. The read must come
// back on its own deadline rather than parking the thread inside OpenSSL.
//
// This drives TlsConnection directly rather than through the listener so the I/O
// timeout can be set to one second - accept_tls_connection takes it as a
// parameter - which makes the scenario fast and its bound unambiguous. Against
// the unfixed code the socket is blocking after the handshake and the second
// read never returns, so this scenario hangs and the suite reports a timeout,
// which is a failure.
SCENARIO("a TLS read returns on its deadline when the peer sends an incomplete record",
         "[homeserver][http][tls][integration][security][m07]")
{
    GIVEN("an established TLS connection with a one-second I/O timeout")
    {
        auto const certificate = write_test_tls_certificate();
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();

        WHEN("the peer completes a handshake, sends one whole record, then half of another")
        {
            auto constexpr io_timeout_ms = 1000;

            // Server side: accept, handshake, then two reads. No Catch2
            // assertions in here - results come back through these locals and
            // are asserted below, after the join.
            auto handshake_ok = false;
            auto first_read = std::ptrdiff_t{0};
            auto second_read = std::ptrdiff_t{0};
            auto second_read_ms = std::int64_t{0};
            auto first_payload = std::string{};

            auto server_thread = std::thread{[&]() {
                auto const accepted = ::accept(acceptor.fd(), nullptr, nullptr);
                if (accepted < 0)
                {
                    return;
                }
                // Owns the accepted descriptor: TlsConnection only borrows it.
                auto const owned_accepted = merovingian::core::SocketHandle{accepted};
                auto accepted_result =
                    merovingian::homeserver::accept_tls_connection(*tls_context.context, accepted, io_timeout_ms);
                if (!accepted_result.ok())
                {
                    return;
                }
                handshake_ok = true;
                auto& connection = *accepted_result.connection;

                // Control read: a complete record must still work. The
                // non-blocking change would be worthless if it broke this.
                auto buffer = std::array<char, 256U>{};
                first_read = connection.read(buffer.data(), buffer.size());
                if (first_read > 0)
                {
                    first_payload.assign(buffer.data(), static_cast<std::size_t>(first_read));
                }

                // The read under test: the peer has sent a record header
                // promising more bytes than it will ever send.
                auto const started = std::chrono::steady_clock::now();
                second_read = connection.read(buffer.data(), buffer.size());
                second_read_ms =
                    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started)
                        .count();
                ::close(accepted);
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

            REQUIRE(send_all_tls(*client_tls, "ping"));
            // Let the control read complete before the malformed record lands,
            // so the two reads cannot be serviced out of order.
            std::this_thread::sleep_for(std::chrono::milliseconds{200});

            // A TLS application-data record header claiming 64 bytes of payload,
            // followed by only 5. Written raw, underneath OpenSSL, because the
            // point is to hand the server an unfinished record. The server's
            // SSL_read wants 59 more bytes that will never arrive.
            auto const truncated_record = std::string{"\x17\x03\x03\x00\x40", 5U} + std::string{"abcde"};
            REQUIRE(send_all(client_socket.native_handle(), truncated_record));

            server_thread.join();

            THEN("the read gives up on its own deadline instead of blocking forever")
            {
                REQUIRE(handshake_ok);
                // Control: the complete record read normally.
                REQUIRE(first_read == 4);
                REQUIRE(first_payload == "ping");
                // The unfinished record yields an error return, not a hang.
                REQUIRE(second_read < 0);
                // Bounded by the connection's own timeout. The lower bound
                // matters too: returning instantly would mean the read was not
                // waiting for the rest of the record at all.
                REQUIRE(second_read_ms >= 500);
                REQUIRE(second_read_ms < 8000);
            }
        }
    }
}

namespace
{

// 0.12.13 audit item 1 (ADR-0072): per-IP connection cap at accept time.

enum class SourceConnect : std::uint8_t
{
    connected,
    source_unavailable,
    failed,
};

// Connects to 127.0.0.1:port from `source`, another loopback address. Linux
// routes all of 127.0.0.0/8 to lo; a host without the alias reports
// source_unavailable, which is the one precondition a scenario may skip on.
[[nodiscard]] auto connect_from(char const* source, std::uint16_t port) -> std::pair<SourceConnect, int>
{
    auto const fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        return {SourceConnect::failed, -1};
    }
    auto local = sockaddr_in{};
    local.sin_family = AF_INET;
    local.sin_port = 0U;
    if (::inet_pton(AF_INET, source, &local.sin_addr) != 1)
    {
        ::close(fd);
        return {SourceConnect::failed, -1};
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (::bind(fd, reinterpret_cast<sockaddr const*>(&local), sizeof(local)) != 0)
    {
        auto const unavailable = errno == EADDRNOTAVAIL;
        ::close(fd);
        return {unavailable ? SourceConnect::source_unavailable : SourceConnect::failed, -1};
    }
    auto remote = sockaddr_in{};
    remote.sin_family = AF_INET;
    remote.sin_port = htons(port);
    remote.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-reinterpret-cast)
    if (::connect(fd, reinterpret_cast<sockaddr const*>(&remote), sizeof(remote)) != 0)
    {
        ::close(fd);
        return {SourceConnect::failed, -1};
    }
    return {SourceConnect::connected, fd};
}

// Sends one keep-alive request and returns the response ("" if the server
// closed the connection without answering). A refused connection may already
// be closed, so a failed send is not an error here.
[[nodiscard]] auto request_on(int fd) -> std::string
{
    std::ignore = send_all(fd, "GET /no-such-route HTTP/1.1\r\nHost: localhost\r\n\r\n");
    auto reader = PlainResponseReader{};
    return receive_response(fd, reader);
}

// True when the server closes the connection within `wait` without being sent
// anything: what a refused connection sees. An admitted one is still waiting
// for the request (or the TLS handshake).
[[nodiscard]] auto closed_by_server_within(int fd, std::chrono::milliseconds wait) -> bool
{
    auto timeout = timeval{};
    timeout.tv_sec = static_cast<decltype(timeout.tv_sec)>(wait.count() / 1000);
    timeout.tv_usec = static_cast<decltype(timeout.tv_usec)>((wait.count() % 1000) * 1000);
    std::ignore = ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    auto byte = std::array<char, 1U>{};
    auto const received = ::recv(fd, byte.data(), byte.size(), 0);
    return received == 0 || (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK);
}

// Stops the listener on every exit from a scenario, including a SKIP or a
// failed REQUIRE: destroying a joinable std::thread would abort the binary.
// ShutdownSignal::fire and ThreadPool::request_stop are both idempotent.
class ServerStop final
{
public:
    ServerStop(merovingian::net::ShutdownSignal& shutdown, std::thread& thread,
               merovingian::net::ThreadPool& pool) noexcept
        : m_shutdown{shutdown}
        , m_thread{thread}
        , m_pool{pool}
    {
    }
    ServerStop(ServerStop const&) = delete;
    auto operator=(ServerStop const&) -> ServerStop& = delete;
    ServerStop(ServerStop&&) = delete;
    auto operator=(ServerStop&&) -> ServerStop& = delete;
    ~ServerStop()
    {
        m_shutdown.fire();
        if (m_thread.joinable())
        {
            m_thread.join();
        }
        m_pool.request_stop();
    }

private:
    merovingian::net::ShutdownSignal& m_shutdown;
    std::thread& m_thread;
    merovingian::net::ThreadPool& m_pool;
};

// Polls until `predicate` holds or `limit` passes; releasing a slot happens on
// the server's worker thread once it sees the client's close.
template <typename Predicate>
[[nodiscard]] auto eventually(Predicate predicate, std::chrono::milliseconds limit) -> bool
{
    auto const deadline = std::chrono::steady_clock::now() + limit;
    while (std::chrono::steady_clock::now() < deadline)
    {
        if (predicate())
        {
            return true;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
    }
    return predicate();
}

} // namespace

SCENARIO("merovingian-server caps the connections one client address may hold open",
         "[homeserver][http][listener][integration][security][connection_limit]")
{
    GIVEN("a plain-HTTP listener with a per-IP cap of two")
    {
        auto config = registration_enabled_config();
        config.server().http.max_connections_per_ip = 2U;
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto shutdown = merovingian::net::ShutdownSignal{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        // Declared after the runtime so it is destroyed first; see the
        // keep-alive cap scenario above.
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{8U};

        WHEN("one address holds two connections open and tries a third, while another address connects")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_http(acceptor, runtime, shutdown, stats,
                                                    merovingian::homeserver::HttpDispatchMode::local_router, pool);
            }};
            auto const stop = ServerStop{shutdown, server_thread, pool};

            // Each held connection completes one keep-alive request and is
            // then parked by the server, still open and still counted.
            auto const first_fd = connect_loopback(port);
            auto const second_fd = connect_loopback(port);
            REQUIRE(first_fd >= 0);
            REQUIRE(second_fd >= 0);
            auto const first_response = request_on(first_fd);
            auto const second_response = request_on(second_fd);

            auto const third_fd = connect_loopback(port);
            REQUIRE(third_fd >= 0);
            auto const third_response = request_on(third_fd);
            ::close(third_fd);

            auto const [other_status, other_fd] = connect_from("127.0.0.2", port);
            if (other_status == SourceConnect::source_unavailable)
            {
                SKIP("127.0.0.2 is not a local address on this host");
            }
            REQUIRE(other_status == SourceConnect::connected);
            auto const other_response = request_on(other_fd);
            ::close(other_fd);

            auto const held_count = runtime.connection_limiter->active("127.0.0.1");

            // Closing a held connection frees its slot for the next one.
            ::close(first_fd);
            auto fourth_response = std::string{};
            auto const fourth_admitted = eventually(
                [&]() {
                    auto const fd = connect_loopback(port);
                    if (fd < 0)
                    {
                        return false;
                    }
                    fourth_response = request_on(fd);
                    ::close(fd);
                    return fourth_response.starts_with("HTTP/1.1 ");
                },
                std::chrono::milliseconds{5000});

            ::close(second_fd);
            auto const all_released = eventually(
                [&]() {
                    return runtime.connection_limiter->tracked_keys() == 0U;
                },
                std::chrono::milliseconds{5000});

            shutdown.fire();
            server_thread.join();
            pool.request_stop();

            THEN("the two held connections were served")
            {
                REQUIRE(first_response.starts_with("HTTP/1.1 "));
                REQUIRE(second_response.starts_with("HTTP/1.1 "));
            }

            THEN("the third connection from the same address was closed without a response")
            {
                INFO("third response: " << third_response);
                REQUIRE(third_response.empty());
                REQUIRE(held_count == 2U);
            }

            THEN("the other address was served")
            {
                REQUIRE(other_response.starts_with("HTTP/1.1 "));
            }

            THEN("closing a held connection let a new one in, and closing all released every slot")
            {
                REQUIRE(fourth_admitted);
                REQUIRE(all_released);
            }
        }
    }
}

SCENARIO("merovingian-server does not cap connections from a trusted reverse proxy",
         "[homeserver][http][listener][integration][connection_limit]")
{
    GIVEN("a per-IP cap of one and 127.0.0.3 configured as a trusted proxy")
    {
        auto config = registration_enabled_config();
        config.server().http.max_connections_per_ip = 1U;
        config.server().trusted_proxies = {"127.0.0.3"};
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto shutdown = merovingian::net::ShutdownSignal{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{8U};

        WHEN("the proxy holds one connection open and opens another")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_http(acceptor, runtime, shutdown, stats,
                                                    merovingian::homeserver::HttpDispatchMode::local_router, pool);
            }};
            auto const stop = ServerStop{shutdown, server_thread, pool};

            auto const [first_status, first_fd] = connect_from("127.0.0.3", port);
            if (first_status == SourceConnect::source_unavailable)
            {
                SKIP("127.0.0.3 is not a local address on this host");
            }
            REQUIRE(first_status == SourceConnect::connected);
            auto const first_response = request_on(first_fd);
            auto const [second_status, second_fd] = connect_from("127.0.0.3", port);
            REQUIRE(second_status == SourceConnect::connected);
            auto const second_response = request_on(second_fd);
            ::close(first_fd);
            ::close(second_fd);

            shutdown.fire();
            server_thread.join();
            pool.request_stop();

            THEN("both are served and no slot is counted for the proxy")
            {
                REQUIRE(first_response.starts_with("HTTP/1.1 "));
                REQUIRE(second_response.starts_with("HTTP/1.1 "));
                REQUIRE(runtime.connection_limiter->active("127.0.0.3") == 0U);
            }
        }
    }
}

SCENARIO("merovingian-server caps connections per address on a TLS listener before the handshake",
         "[homeserver][http][listener][tls][integration][security][connection_limit]")
{
    GIVEN("a TLS listener with a per-IP cap of one")
    {
        auto const certificate = write_test_tls_certificate();
        auto tls_context = merovingian::homeserver::make_tls_server_context(certificate.certificate_file,
                                                                            certificate.private_key_file);
        REQUIRE(tls_context.ok());

        auto config = registration_enabled_config();
        config.server().http.max_connections_per_ip = 1U;
        auto runtime_result = merovingian::homeserver::start_client_server(config);
        REQUIRE(runtime_result.started);

        auto acceptor = merovingian::net::TcpAcceptor{};
        REQUIRE(acceptor.bind("127.0.0.1", 0U).ok);
        auto const port = acceptor.bound_port();
        REQUIRE(port > 0U);

        auto shutdown = merovingian::net::ShutdownSignal{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        auto runtime = std::move(runtime_result.runtime);
        auto pool = merovingian::net::ThreadPool{8U};

        WHEN("one address holds a connection in the handshake and opens a second")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_tls_http(*tls_context.context, acceptor, runtime, shutdown, stats,
                                                        merovingian::homeserver::HttpDispatchMode::local_router, pool);
            }};
            auto const stop = ServerStop{shutdown, server_thread, pool};

            auto const held_fd = connect_loopback(port);
            REQUIRE(held_fd >= 0);
            // The server now waits for this connection's ClientHello.
            std::this_thread::sleep_for(std::chrono::milliseconds{200});
            auto const second_fd = connect_loopback(port);
            REQUIRE(second_fd >= 0);
            auto const second_refused = closed_by_server_within(second_fd, std::chrono::milliseconds{2000});
            auto const held_still_open = !closed_by_server_within(held_fd, std::chrono::milliseconds{200});
            ::close(second_fd);
            ::close(held_fd);
            auto const all_released = eventually(
                [&]() {
                    return runtime.connection_limiter->tracked_keys() == 0U;
                },
                std::chrono::milliseconds{20000});

            shutdown.fire();
            server_thread.join();
            pool.request_stop();

            THEN("the second is closed at once, the held one stays open, and closing it released its slot")
            {
                REQUIRE(second_refused);
                REQUIRE(held_still_open);
                REQUIRE(all_released);
            }
        }
    }
}
