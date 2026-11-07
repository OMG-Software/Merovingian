// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::http
{

// HTTP protocol version of a request's start line. Drives the persistent
// connection decision: HTTP/1.1 defaults to keep-alive, HTTP/1.0 defaults to
// close (RFC 9112 §9.3 "Connection").
enum class HttpVersion : std::uint8_t
{
    http_1_0,
    http_1_1,
};

} // namespace merovingian::http
