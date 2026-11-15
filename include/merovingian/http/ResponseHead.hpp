// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/Error.hpp"
#include "merovingian/http/ConnectionPreference.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

// The HTTP/1.1 response head every listener writes (homeserver/HttpServer.cpp, plain and TLS alike). A handler's
// headers are written in its order, then the transport's own: `X-Content-Type-Options: nosniff` unless the handler
// sent it, `Content-Length`, `Content-Type` (the handler's, else `application/json`) and `Connection`
// (`Keep-Alive` too when the connection is kept).
namespace merovingian::http
{

// The reason phrase of a status this server answers with; an empty phrase for any other (RFC 9112 section 4 allows
// one, and "OK" on an unlisted status misleads).
[[nodiscard]] auto reason_phrase(std::uint16_t status) noexcept -> std::string_view;

// The head for a body of `body_length` bytes. Refused (ErrorCode::invalid_argument, fixed message, never the
// header), and nothing is repaired or dropped, when (ADR-0767):
//  - `status` is outside 200-599;
//  - a header name is not an RFC 9110 token, or a value holds a control character other than HTAB (so no CR or LF
//    can end the line early and start another header or the body);
//  - a header is `Content-Length`, `Transfer-Encoding`, `Connection` or `Keep-Alive` in any case: the transport
//    alone frames the response;
//  - `Content-Type` comes twice in any case, or `X-Content-Type-Options` comes twice or with a value other than
//    `nosniff`.
// Names are matched case-insensitively. An empty `Content-Type` value means the default.
[[nodiscard]] auto format_response_head(std::uint16_t status, std::uint64_t body_length,
                                        std::vector<std::pair<std::string, std::string>> const& headers,
                                        ConnectionPreference connection, std::uint32_t keep_alive_timeout_seconds)
    -> std::variant<std::string, core::Error>;

// format_response_head followed by `body`; refused when the head is.
[[nodiscard]] auto format_response(std::uint16_t status, std::string_view body,
                                   std::vector<std::pair<std::string, std::string>> const& headers,
                                   ConnectionPreference connection, std::uint32_t keep_alive_timeout_seconds)
    -> std::variant<std::string, core::Error>;

} // namespace merovingian::http
