// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

struct ssl_ctx_st;
struct ssl_st;

namespace merovingian::homeserver
{

struct TlsServerContextResult;
struct TlsConnectionResult;

class TlsServerContext final
{
public:
    TlsServerContext() = delete;
    ~TlsServerContext();

    TlsServerContext(TlsServerContext const&) = delete;
    auto operator=(TlsServerContext const&) -> TlsServerContext& = delete;

    TlsServerContext(TlsServerContext&& other) noexcept;
    auto operator=(TlsServerContext&& other) noexcept -> TlsServerContext&;

    [[nodiscard]] auto native_handle() const noexcept -> ssl_ctx_st&;

private:
    explicit TlsServerContext(ssl_ctx_st& context) noexcept;

    ssl_ctx_st* m_context;

    friend struct TlsServerContextResult;
    friend auto make_tls_server_context(std::string const& certificate_file, std::string const& private_key_file)
        -> TlsServerContextResult;
};

struct TlsServerContextResult final
{
    std::optional<TlsServerContext> context{};
    std::string error{};

    [[nodiscard]] auto ok() const noexcept -> bool;
};

class TlsConnection final
{
public:
    TlsConnection() = delete;
    ~TlsConnection();

    TlsConnection(TlsConnection const&) = delete;
    auto operator=(TlsConnection const&) -> TlsConnection& = delete;

    TlsConnection(TlsConnection&& other) noexcept;
    auto operator=(TlsConnection&& other) noexcept -> TlsConnection&;

    [[nodiscard]] auto fd() const noexcept -> int;
    // True when OpenSSL already holds input read off the socket (a decrypted
    // record not yet returned, or raw bytes not yet processed). poll() on the
    // descriptor cannot see these, so a caller waiting for input must check
    // this first or it waits for bytes that have already arrived.
    [[nodiscard]] auto has_pending_input() const noexcept -> bool;
    [[nodiscard]] auto read(char* buffer, std::size_t capacity) noexcept -> std::ptrdiff_t;
    [[nodiscard]] auto write(std::string_view data) noexcept -> std::ptrdiff_t;

private:
    TlsConnection(ssl_st& connection, int file_descriptor, int io_timeout_milliseconds) noexcept;

    // Shared retry loop behind read() and write(). `reading` selects SSL_read_ex
    // or SSL_write_ex; both need identical WANT_READ/WANT_WRITE handling against
    // a deadline, and duplicating it invites the two paths to drift.
    [[nodiscard]] auto pump(bool reading, void* buffer, std::size_t length, std::size_t& transferred) noexcept
        -> std::ptrdiff_t;

    ssl_st* m_connection;
    int m_fd;
    // M-07: the socket stays non-blocking for the life of the connection, so
    // read() and write() drive OpenSSL's WANT_READ/WANT_WRITE themselves and
    // must carry their own deadline. Previously the fd was restored to blocking
    // after the handshake, which let a partial TLS record park a worker thread
    // inside SSL_read indefinitely — the caller's poll() only proves that TCP
    // bytes arrived, never that a whole TLS record did.
    int m_io_timeout_ms;

    friend struct TlsConnectionResult;
    friend auto accept_tls_connection(TlsServerContext& context, int client_fd, int timeout_milliseconds)
        -> TlsConnectionResult;
};

struct TlsConnectionResult final
{
    std::optional<TlsConnection> connection{};
    std::string error{};

    [[nodiscard]] auto ok() const noexcept -> bool;
};

[[nodiscard]] auto make_tls_server_context(std::string const& certificate_file, std::string const& private_key_file)
    -> TlsServerContextResult;

[[nodiscard]] auto accept_tls_connection(TlsServerContext& context, int client_fd, int timeout_milliseconds)
    -> TlsConnectionResult;

} // namespace merovingian::homeserver
