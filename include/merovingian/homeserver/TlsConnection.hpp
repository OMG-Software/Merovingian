// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>
#include <string_view>

struct ssl_st;

namespace merovingian::homeserver
{

class TlsServerContext;
struct TlsConnectionResult;

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

} // namespace merovingian::homeserver
