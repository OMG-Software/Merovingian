// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/Tls.hpp"

#include "merovingian/homeserver/TlsConnection.hpp"
#include "merovingian/homeserver/TlsConnectionResult.hpp"
#include "merovingian/homeserver/TlsServerContext.hpp"
#include "merovingian/homeserver/TlsServerContextResult.hpp"
#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/observability/StructuredLogField.hpp"
#include "merovingian/platform/FileMetadataSupport.hpp"

#include <fcntl.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <poll.h>

#include <cerrno>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <limits>
#include <memory>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{
namespace
{

    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("tls", event, fields, severity);
    }

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
            std::ignore = ::fcntl(fd, F_SETFL, original_flags);
        }
    }

} // namespace

// Shared by TlsConnection::pump and the handshake loop in accept_tls_connection.
[[nodiscard]] auto poll_for_tls(int fd, int ssl_error, int timeout_milliseconds) noexcept -> bool
{
    auto entry = pollfd{};
    entry.fd = fd;
    entry.events = ssl_error == SSL_ERROR_WANT_WRITE ? POLLOUT : POLLIN;
    auto const result = ::poll(&entry, 1U, timeout_milliseconds);
    return result > 0 && (entry.revents & entry.events) != 0;
}

namespace
{

    struct BioDeleter final
    {
        auto operator()(BIO* bio) const noexcept -> void
        {
            BIO_free(bio);
        }
    };

    struct EvpPkeyDeleter final
    {
        auto operator()(EVP_PKEY* key) const noexcept -> void
        {
            EVP_PKEY_free(key);
        }
    };

    // A PEM private key of any size an operator would deploy (an RSA-16384 key
    // is about 13 KiB); anything larger is not a key.
    constexpr auto max_private_key_bytes = std::size_t{64U * 1024U};

    // ISO-7: the key is validated and read through one descriptor
    // (O_NOFOLLOW, regular file, owned by this user, mode 0400) into locked
    // memory, and OpenSSL parses it from there. Loading it by path with
    // SSL_CTX_use_PrivateKey_file reopened a name that the startup metadata
    // check had inspected separately, so a swap or symlink in between was loaded.
    [[nodiscard]] auto read_private_key(std::string const& private_key_file)
        -> std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>
    {
        auto const pem = platform::read_secure_secret_file(private_key_file, max_private_key_bytes);
        if (!pem.has_value() || pem->bytes().size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        {
            return {};
        }
        auto const bio = std::unique_ptr<BIO, BioDeleter>{
            BIO_new_mem_buf(pem->bytes().data(), static_cast<int>(pem->bytes().size()))};
        if (!bio)
        {
            return {};
        }
        return std::unique_ptr<EVP_PKEY, EvpPkeyDeleter>{PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr)};
    }

} // namespace

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

    // Security audit 2026-09 L-04: "HIGH:!aNULL:!MD5:!RC4:!3DES" still allowed
    // plain-RSA key exchange (no forward secrecy) and CBC/HMAC suites -- a
    // later compromise of the server's RSA private key could retrospectively
    // decrypt recorded traffic. Restrict to authenticated ephemeral
    // (ECDHE/DHE) AEAD suites only. This list governs TLS 1.2 and below only;
    // TLS 1.3 ciphersuites are negotiated separately via OpenSSL's compiled-in
    // defaults (SSL_CTX_set_ciphersuites is never called here) and are
    // unaffected.
    if (SSL_CTX_set_cipher_list(context.m_context,
                                "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:!aNULL:!MD5:!RC4:!3DES:!RSA:!SHA1") != 1)
    {
        return {{}, openssl_error_string("unable to configure TLS cipher list")};
    }

    if (SSL_CTX_use_certificate_chain_file(context.m_context, certificate_file.c_str()) != 1)
    {
        return {{}, openssl_error_string("unable to load TLS certificate chain")};
    }

    auto const private_key = read_private_key(private_key_file);
    if (!private_key)
    {
        return {{},
                openssl_error_string("unable to load TLS private key: it must be a regular, non-symlink file "
                                     "owned by this user with mode 0400")};
    }
    if (SSL_CTX_use_PrivateKey(context.m_context, private_key.get()) != 1)
    {
        return {{}, openssl_error_string("unable to load TLS private key")};
    }

    if (SSL_CTX_check_private_key(context.m_context) != 1)
    {
        auto const error = openssl_error_string("TLS private key does not match certificate");
        log_diagnostic("context.rejected", {
                                               {"cert_file", certificate_file, false},
                                               {"reason",    error,            false}
        });
        return {{}, error};
    }

    log_diagnostic("context.ready",
                   {
                       {"cert_file", certificate_file, false}
    },
                   observability::LogEventSeverity::info);
    return {std::optional<TlsServerContext>{std::move(context)}, {}};
}

auto accept_tls_connection(TlsServerContext& context, int client_fd, int timeout_milliseconds) -> TlsConnectionResult
{
    auto* raw_connection = SSL_new(&context.native_handle());
    if (raw_connection == nullptr)
    {
        return {{}, openssl_error_string("unable to create TLS connection")};
    }

    auto connection = TlsConnection{*raw_connection, client_fd, timeout_milliseconds};
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
            // M-07: deliberately do NOT restore blocking mode here. The socket
            // stays non-blocking for the life of the connection so that
            // TlsConnection::pump() can bound every read and write by its own
            // deadline. Restoring blocking mode was the defect: the HTTP layer's
            // poll() proves only that TCP bytes are available, not that a
            // complete TLS record is, so SSL_read on a blocking socket could
            // park a worker thread indefinitely on a record the peer never
            // finished sending — entirely outside the server's request timeouts.
            log_diagnostic("handshake.accepted", {
                                                     {"fd", std::to_string(client_fd), false}
            });
            return {std::optional<TlsConnection>{std::move(connection)}, {}};
        }

        auto const ssl_error = SSL_get_error(connection.m_connection, accept_result);
        if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE)
        {
            restore_flags(client_fd, original_flags);
            auto const error = openssl_error_string("TLS handshake failed");
            log_diagnostic("handshake.rejected",
                           {
                               {"fd",     std::to_string(client_fd), false},
                               {"reason", error,                     false}
            });
            return {{}, error};
        }

        auto const elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
        auto const remaining = timeout_milliseconds - static_cast<int>(elapsed.count());
        if (remaining <= 0 || !poll_for_tls(client_fd, ssl_error, remaining))
        {
            restore_flags(client_fd, original_flags);
            log_diagnostic("handshake.rejected",
                           {
                               {"fd",     std::to_string(client_fd), false},
                               {"reason", "TLS handshake timed out", false}
            });
            return {{}, "TLS handshake timed out"};
        }
    }
}

} // namespace merovingian::homeserver
