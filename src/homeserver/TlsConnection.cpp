// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/TlsConnection.hpp"

#include "merovingian/homeserver/Tls.hpp"

#include <openssl/ssl.h>

#include <chrono>
#include <cstddef>
#include <string_view>
#include <utility>

namespace merovingian::homeserver
{

TlsConnection::TlsConnection(ssl_st& connection, int file_descriptor, int io_timeout_milliseconds) noexcept
    : m_connection{&connection}
    , m_fd{file_descriptor}
    , m_io_timeout_ms{io_timeout_milliseconds}
{
}

TlsConnection::~TlsConnection()
{
    SSL_free(m_connection);
}

TlsConnection::TlsConnection(TlsConnection&& other) noexcept
    : m_connection{std::exchange(other.m_connection, nullptr)}
    , m_fd{std::exchange(other.m_fd, -1)}
    , m_io_timeout_ms{std::exchange(other.m_io_timeout_ms, 0)}
{
}

auto TlsConnection::operator=(TlsConnection&& other) noexcept -> TlsConnection&
{
    if (this != &other)
    {
        SSL_free(m_connection);
        m_connection = std::exchange(other.m_connection, nullptr);
        m_fd = std::exchange(other.m_fd, -1);
        m_io_timeout_ms = std::exchange(other.m_io_timeout_ms, 0);
    }
    return *this;
}

auto TlsConnection::fd() const noexcept -> int
{
    return m_fd;
}

auto TlsConnection::has_pending_input() const noexcept -> bool
{
    if (m_connection == nullptr)
    {
        return false;
    }
    // OpenBSD's LibreSSL does not provide SSL_has_pending; SSL_pending is sufficient
    // to detect buffered application data on all supported TLS stacks.
#if defined(LIBRESSL_VERSION_NUMBER)
    return SSL_pending(m_connection) > 0;
#else
    return SSL_pending(m_connection) > 0 || SSL_has_pending(m_connection) == 1;
#endif
}

// M-07: the socket is non-blocking for the connection's whole life, so an
// incomplete TLS record surfaces as SSL_ERROR_WANT_READ rather than blocking
// inside OpenSSL. Both I/O paths therefore pump the same wait loop: retry the
// SSL call, and when it wants more socket readiness, poll for it against a
// deadline. Returning -1 on expiry means a peer that opens a record and stops
// costs one bounded timeout instead of a permanently parked worker thread.
//
// OpenSSL requires that a retried call use the SAME arguments as the call that
// returned WANT_READ/WANT_WRITE, which is why the buffer and length are hoisted
// out of the loop rather than advanced across iterations.
auto TlsConnection::pump(bool const reading, void* const buffer, std::size_t const length,
                         std::size_t& transferred) noexcept -> std::ptrdiff_t
{
    auto const started = std::chrono::steady_clock::now();
    while (true)
    {
        transferred = 0U;
        auto const result = reading ? SSL_read_ex(m_connection, buffer, length, &transferred)
                                    : SSL_write_ex(m_connection, buffer, length, &transferred);
        if (result == 1)
        {
            return static_cast<std::ptrdiff_t>(transferred);
        }

        auto const ssl_error = SSL_get_error(m_connection, result);
        if (ssl_error != SSL_ERROR_WANT_READ && ssl_error != SSL_ERROR_WANT_WRITE)
        {
            // A clean shutdown or a real protocol error: nothing to wait for.
            return -1;
        }

        auto const elapsed =
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - started);
        auto const remaining = m_io_timeout_ms - static_cast<int>(elapsed.count());
        if (remaining <= 0 || !poll_for_tls(m_fd, ssl_error, remaining))
        {
            return -1;
        }
    }
}

auto TlsConnection::read(char* buffer, std::size_t capacity) noexcept -> std::ptrdiff_t
{
    auto received = std::size_t{0U};
    return pump(true, buffer, capacity, received);
}

auto TlsConnection::write(std::string_view data) noexcept -> std::ptrdiff_t
{
    auto written = std::size_t{0U};
    // SSL_write_ex takes a non-const pointer but does not modify the buffer.
    return pump(false, const_cast<char*>(data.data()), data.size(), written); // NOLINT(*-const-cast)
}

} // namespace merovingian::homeserver
