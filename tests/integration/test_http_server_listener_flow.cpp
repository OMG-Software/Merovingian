// SPDX-License-Identifier: GPL-3.0-or-later

#include "../support/registration_token.hpp"
#include "merovingian/config/config.hpp"
#include "merovingian/core/socket_handle.hpp"
#include "merovingian/homeserver/client_server.hpp"
#include "merovingian/homeserver/http_server.hpp"
#include "merovingian/net/thread_pool.hpp"
#include "merovingian/homeserver/tls.hpp"
#include "merovingian/net/shutdown_signal.hpp"
#include "merovingian/net/tcp_acceptor.hpp"

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <memory>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <sys/socket.h>
#include <unistd.h>

namespace
{

[[nodiscard]] auto registration_enabled_config() -> merovingian::config::Config
{
    auto security = merovingian::config::SecurityConfig{};
    merovingian::tests::enable_token_registration(security);
    return {
        merovingian::config::ServerConfig{},
        merovingian::config::ListenersConfig{},
        merovingian::config::DatabaseConfig{},
        security,
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

[[nodiscard]] auto receive_tls_until_close(SSL& connection) -> std::string
{
    auto output = std::string{};
    auto buffer = std::array<char, 4096U>{};
    while (true)
    {
        auto received = std::size_t{0U};
        if (SSL_read_ex(&connection, buffer.data(), buffer.size(), &received) != 1 || received == 0U)
        {
            break;
        }
        output.append(buffer.data(), received);
    }
    return output;
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

[[nodiscard]] auto write_test_tls_certificate() -> TlsTestCertificate
{
    static auto counter = std::uint32_t{0U};
    auto const directory = std::filesystem::temp_directory_path() /
                           ("merovingian-tls-" + std::to_string(::getpid()) + "-" + std::to_string(++counter));
    std::filesystem::create_directories(directory);

    auto key = std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>{EVP_RSA_gen(2048U)};
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
        auto runtime_lock = std::mutex{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        auto pool = merovingian::net::ThreadPool{4U};
        auto runtime = std::move(runtime_result.runtime);

        WHEN("a client sends an HTTP/1.1 request to an unknown route")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_http(acceptor, runtime, runtime_lock, shutdown, stats,
                                                    merovingian::homeserver::HttpDispatchMode::local_router, pool);
            }};

            auto const client_fd = connect_loopback(port);
            REQUIRE(client_fd >= 0);

            auto const request = std::string{"GET /no-such-route HTTP/1.1\r\nHost: localhost\r\n\r\n"};
            REQUIRE(send_all(client_fd, request));

            auto const response = receive_until_close(client_fd);
            ::close(client_fd);

            shutdown.fire();
            server_thread.join();

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
        auto runtime_lock = std::mutex{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        auto pool = merovingian::net::ThreadPool{4U};
        auto runtime = std::move(runtime_result.runtime);

        WHEN("a TLS client sends Matrix JSON registration over TCP")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_tls_http(*tls_context.context, acceptor, runtime, runtime_lock, shutdown,
                                                        stats,
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
            auto const response = receive_tls_until_close(*client_tls);

            shutdown.fire();
            server_thread.join();

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
        auto runtime_lock = std::mutex{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        auto pool = merovingian::net::ThreadPool{4U};
        auto runtime = std::move(runtime_result.runtime);

        WHEN("a client sends Matrix JSON registration over TCP")
        {
            auto server_thread = std::thread{[&]() {
                merovingian::homeserver::serve_http(acceptor, runtime, runtime_lock, shutdown, stats,
                                                    merovingian::homeserver::HttpDispatchMode::client_server, pool);
            }};

            auto const body = merovingian::tests::registration_json("alice", "CorrectHorse7!");
            auto const request = "POST /_matrix/client/v3/register HTTP/1.1\r\nHost: localhost\r\nContent-Length: " +
                                 std::to_string(body.size()) + "\r\n\r\n" + body;

            auto const client_fd = connect_loopback(port);
            REQUIRE(client_fd >= 0);
            REQUIRE(send_all(client_fd, request));
            auto const response = receive_until_close(client_fd);
            ::close(client_fd);

            shutdown.fire();
            server_thread.join();

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
        auto runtime_lock = std::mutex{};
        auto stats = merovingian::homeserver::HttpServeStats{};
        auto pool = merovingian::net::ThreadPool{4U};
        auto runtime = std::move(runtime_result.runtime);

        auto server_thread = std::thread{[&]() {
            merovingian::homeserver::serve_http(acceptor, runtime, runtime_lock, shutdown, stats,
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
            auto const follow_response = receive_until_close(follow_fd);
            ::close(follow_fd);

            shutdown.fire();
            server_thread.join();

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
