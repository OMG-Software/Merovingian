// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string_view>

namespace merovingian::http
{

// Reasons the outbound HTTP client may refuse or fail a request.
// Each value maps to a stable, audit-friendly name through outbound_error_name.
// Failures fail closed: the response payload is meaningless when ok is false,
// except for redirect_rejected where the 3xx status and headers are preserved
// in the response so callers can audit the rejection.
enum class OutboundError : std::uint8_t
{
    none,
    invalid_url,
    invalid_method,
    https_required,
    unresolved_host,
    tls_verification_failed,
    connection_failed,
    redirect_rejected,
    response_too_large,
    timeout,
    network_error,
    // A header name that is not an RFC 9110 token, or a value with a control character other
    // than HTAB (CR/LF would add header lines: security audit run-1). Refused before any I/O.
    invalid_header,
};

// Returns a stable, audit-friendly name for the given error code.
// The returned view is suitable for logging and structured audit events;
// it is not part of any Matrix wire protocol.
[[nodiscard]] auto outbound_error_name(OutboundError error) noexcept -> std::string_view;

// Parses the stable name produced by outbound_error_name back into an
// OutboundError. Returns OutboundError::network_error for unknown or empty
// names so failures deserialize fail-closed.
[[nodiscard]] auto outbound_error_from_name(std::string_view name) noexcept -> OutboundError;

} // namespace merovingian::http
