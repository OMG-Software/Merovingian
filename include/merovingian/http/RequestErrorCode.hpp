// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::http
{

enum class RequestErrorCode : std::uint8_t
{
    none,
    malformed_request_line,
    invalid_method,
    invalid_target,
    start_line_too_large,
    headers_too_large,
    too_many_headers,
    duplicate_content_length,
    invalid_content_length,
    body_too_large,
    unsupported_transfer_encoding,
};

} // namespace merovingian::http
