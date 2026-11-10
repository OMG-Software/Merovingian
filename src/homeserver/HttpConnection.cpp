// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/homeserver/HttpConnection.hpp"

#include "merovingian/observability/LogEventSeverity.hpp"
#include "merovingian/observability/SingleLog.hpp"
#include "merovingian/observability/StructuredLogField.hpp"

#include <sys/socket.h>

#include <chrono>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

namespace
{

    // Logged under the `http_server` module, like the rest of the transport.
    auto log_diagnostic(std::string_view event, std::vector<observability::StructuredLogField> fields,
                        observability::LogEventSeverity severity = observability::LogEventSeverity::debug) -> void
    {
        observability::log_diagnostic("http_server", event, fields, severity);
    }

} // namespace

HttpConnection::HttpConnection(core::SocketHandle client_socket, HttpDispatchMode dispatch_mode, std::string peer,
                               std::string key) noexcept
    : socket{std::move(client_socket)}
    , mode{dispatch_mode}
    , peer_addr{std::move(peer)}
    , client_key{std::move(key)}
    , opened_at{std::chrono::steady_clock::now()}
{
}

HttpConnection::~HttpConnection()
{
    tls.reset();
    if (socket.valid())
    {
        std::ignore = ::shutdown(socket.native_handle(), SHUT_RDWR);
    }
}

auto HttpConnection::on_park_expired() noexcept -> void
{
    try
    {
        if (first_request)
        {
            log_diagnostic("connection.first_byte_timeout",
                           {
                               {"phase", tls_handshake_owed ? "tls_handshake" : "request", false}
            });
        }
        else
        {
            log_diagnostic("connection.keep_alive_idle_expired", {});
        }
    }
    catch (...)
    {
    }
}

} // namespace merovingian::homeserver
