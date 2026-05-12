// SPDX-License-Identifier: GPL-3.0-or-later

#include <cerrno>
#include <chrono>
#include <cstring>
#include <string>
#include <utility>

#include <fcntl.h>
#include <merovingian/homeserver/tls.hpp>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <poll.h>

namespace merovingian::homeserver
{
namespace
{

    [[nodiscard]] auto openssl_error_string(std::string_view fallback) -> std::string
    {
        auto const code = ERR_get_error();
        if (code == 0U)
        {
            return std::string{fallback};
        }

        auto buffer = std::string(256U, '\0');
        ERR_error_string_n(code, buffer.data(), buffer.size());
        buffer.resize(std::strlen(buffer.c_str()));
        return buffer;
    }

    [[nodiscard]] auto poll_for_tls(int fd, int ssl_error, int timeout_milliseconds) noexcept -> bool
    {
        auto entry = pollfd{};
        entry.fd = fd;
        entry.events = ssl_error == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN;
        auto const result = ::poll(&entry, 1U, timeout_milliseconds);
        return result > 0 && (entry.revents & entry.events) != 0;
    }

    [[nodiscard]] auto set_nonblocking(int fd, int& original_flags) noexcept -> bool
    {
        original_flags = ::fcntl(fd, F_GETFL, 0);
        if (original_flags < 0)
        {
            return false;
        }

        return ::fcntl(fd, F_SETFL, original_flags | O_NONBLOCK) == 0;
    }

    auto restore_flags(int fd, int original_flags) noexcept -> void
    {
        if (original_flags >= 0)
        {
            static_cast<void>(::fcntl(fd, F_SETFL, original_flags));
        }
    }

} // namespace

TlsServerContext::TlsServerContext(ssl_ctx_st& context) noexcept : m_context{&context}
{
}

TlsServerContext::~TlsServerContext()
{
    SSL_CTX_free(m_context);
}

TlsServerContext::TlsServerContext(TlsServerContext&& other) noexcept
    : m_context{std::exchange(other.m_context, nullptr)}
{
}

auto TlsServerContext::operator=(TlsServerContext&& other) noexcept -> TlsServerContext&
{
    if (this != &other)
    {
        SSL_CTX_free(m_context);
        m_context = std::exchange(other.m_context, nullptr);
    }
    return *this;
}

auto TlsServerContext::native_handle() const noexcept -> ssl_ctx_st&
{
    return *m_context;
}

auto TlsServerContextResult::ok() const noexcept -> bool
{
    return context.has_value();
}

TlsConnection::TlsConnection(ssl_st& connection, int file_descriptor) noexcept
    : m_connection{&connection}, m_fd{file_descriptor}
{
}

TlsConnection::~TlsConnection()
{
    SSL_free(m_connection);
}

TlsConnection::TlsConnection(TlsConnection&& other) noexcept
    : m_connection{std::exchange(other.m_connection, nullptr)}, m_fd{std::exchange(other.m_fd, -1)}
{
}

auto TlsConnection::operator=(TlsConnection&& other) noexcept -> TlsConnection&
{
    if (this != &other)
    {
        SSL_free(m_connection);
        m_connection = std::exchange(other.m_connection, nullptr);
        m_fd = std::exchange(other.m_fd, -1);
    }
    return *this;
}

auto TlsConnection::fd() const noexcept -> int
{
    return m_fd;
}

auto TlsConnection::read(char* buffer, std::size_t capacity) noexcept -> std::ptrdiff_t
{
    auto received = std::size_t{0U};
    if (SSL_read_ex(m_connection, buffer, capacity, &received) != 1)
    {
        return -1;
    }
    return static_cast<std::ptrdiff_t>(received);
}

auto TlsConnection::write(std::string_view data) noexcept -> std::ptrdiff_t
{
    auto written = std::size_t{0U};
    if (SSL_write_ex(m_connection, data.data(), data.size(), &written) != 1)
    {
        return -1;
    }
    return static_cast<std::ptrdiff_t>(written);
}

auto TlsConnectionResult::ok() const noexcept -> bool
{
    return connection.has_value();
}

auto make_tls_server_context(std::string const& certificate_file, std::string const& private_key_file)
    -> TlsServerContextResult
{
    if (OPENSSL_init_ssl(0U, nullptr) != 1)
    {
        return {{}, openssl_error_string("OpenSSL initialisation failed")};
    }

    auto* raw_context = SSL_CTX_new(TLS_server_method());
    if (raw_context == nullptr)
    {
        return {{}, openssl_error_string("unable to create TLS server context")};
    }

    auto context = TlsServerContext{*raw_context};
    SSL_CTX_set_options(context.m_context, SSL_OP_NO_COMPRESSION | SSL_OP_CIPHER_SERVER_PREFERENCE);
#ifdef SSL_OP_NO_RENEGOTIATION
    SSL_CTX_set_options(context.m_context, SSL_OP_NO_RENEGOTIATION);
#endif

    if (SSL_CTX_set_min_proto_version(context.m_context, TLS1_2_VERSION) != 1)
    {
        return {{}, openssl_error_string("unable to enforce TLS minimum protocol version")};
    }

    if (SSL_CTX_set_cipher_list(context.m_context, "HIGH:!aNULL:!MD5:!RC4:!3DES") != 1)
    {
        return {{}, openssl_error_string("unable to configure TLS cipher list")};
    }

    if (SSL_CTX_use_certificate_chain_file(context.m_context, certificate_file.c_str()) != 1)
    {
        return {{}, openssl_error_string("unable to load TLS certificate chain")};
    }

    if (SSL_CTX_use_PrivateKey_file(context.m_context, private_key_file.c_str(), SSL_FILETYPE_PEM) != 1)
    {
        return {{}, openssl_error_string("unable to load TLS private key")};
    }

    if (SSL_CTX_check_private_key(context.m_context) != 1)
    {
        return {{}, openssl_error_string("TLS private key does not match certificate")};
    }

    return {std::optional<TlsServerContext>{std::move(context)}, {}};
}

auto accept_tls_connection(TlsServerContext& context, int client_fd, int timeout_milliseconds) -> TlsConnectionResult
{
    auto* raw_connection = SSL_new(&context.native_handle());
    if (raw_connection == nullptr)
    {
        return {{}, openssl_error_string("unable to create TLS connection")};
    }

    auto connection = TlsConnection{*raw_connection, client_fd};
    if (SSL_set_fd(connection.m_connection, client_fd) != 1)
    {
        return {{}, openssl_error_string("unable to attach socket to TLS connection")};
    }

    auto original_flags = int{-1};
    if (!set_nonblocking(client_fd, original_flags))
    {
        return {{}, std::string{"unable to make TLS socket non-blocking: "} + std::strerror(errno)};
    }

    auto const started = std::chrono::steady_clock::now();
    while (true)
    {
        auto const accept_result = SSL_accept(connection.m_connection);
        if (accept_result == 1)
        {
            restore_flags(client_fd, original_flags);
            return {std::optional<TlsConnection>{std::move(connection)}, {}};
        }

        auto const ssl_error = SSL_get_error(connection.m_connection, accept_result);
        if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE)
        {
            restore_flags(client_fd, original_flags);
            return {{}, openssl_error_string("TLS handshake failed")};
        }

        auto const elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
        auto const remaining = timeout_milliseconds - static_cast<int>(elapsed.count());
        if (remaining <= 0 || !poll_for_tls(client_fd, ssl_error, remaining))
        {
            restore_flags(client_fd, original_flags);
            return {{}, "TLS handshake timed out"};
        }
    }
}

} // namespace merovingian::homeserver
