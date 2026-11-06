// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/outbound_client.hpp"

#include <cstdint>
#include <string>

namespace merovingian::appservice
{

// Why a ping did not succeed, as the client-server ping endpoint reports it
// (Application Service API, "Pinging"): 400 M_URL_NOT_SET, 502 M_CONNECTION_FAILED,
// 502 M_BAD_STATUS and 504 M_CONNECTION_TIMEOUT.
enum class AppservicePingFailure : std::uint8_t
{
    none,
    url_not_set,
    connection_failed,
    connection_timeout,
    bad_status,
};

// Outcome of `POST /_matrix/app/v1/ping`. `duration_ms` is how long the request took from this
// homeserver's point of view. For `bad_status`, `status` is the appservice's HTTP status and
// `body` its response body text, cut to max_ping_body_bytes; both are untrusted text.
struct AppservicePingResult final
{
    AppservicePingFailure failure{AppservicePingFailure::none};
    std::uint16_t status{0U};
    std::string body{};
    std::int64_t duration_ms{0};
    http::OutboundError error{http::OutboundError::none};
    std::string error_detail{};

    [[nodiscard]] auto ok() const noexcept -> bool
    {
        return failure == AppservicePingFailure::none;
    }
};

} // namespace merovingian::appservice
