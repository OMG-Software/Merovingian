// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/TlsConnection.hpp"          // split-shim
#include "merovingian/homeserver/TlsConnectionResult.hpp"    // split-shim
#include "merovingian/homeserver/TlsServerContext.hpp"       // split-shim
#include "merovingian/homeserver/TlsServerContextResult.hpp" // split-shim

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

// Waits up to `timeout_milliseconds` for the readiness an OpenSSL WANT_READ or
// WANT_WRITE error asks for. True when the descriptor became ready.
[[nodiscard]] auto poll_for_tls(int fd, int ssl_error, int timeout_milliseconds) noexcept -> bool;

[[nodiscard]] auto make_tls_server_context(std::string const& certificate_file,
                                           std::string const& private_key_file) -> TlsServerContextResult;

[[nodiscard]] auto accept_tls_connection(TlsServerContext& context, int client_fd,
                                         int timeout_milliseconds) -> TlsConnectionResult;

} // namespace merovingian::homeserver
