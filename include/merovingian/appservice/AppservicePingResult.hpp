// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/appservice/AppservicePingFailure.hpp"
#include "merovingian/http/OutboundError.hpp"

#include <cstdint>
#include <string>

namespace merovingian::appservice
{

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
