// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/outbound_error.hpp"

#include <cstdint>
#include <string>

namespace merovingian::appservice
{

// Outcome of one outbound call. `disabled` is set when the appservice's
// registration has `url: null` ("no traffic is required" per spec) — the
// caller made no network attempt at all.
struct AppserviceCallResult final
{
    bool ok{false};
    bool disabled{false};
    std::uint16_t status{0U};
    http::OutboundError error{http::OutboundError::none};
    std::string error_detail{};
};

} // namespace merovingian::appservice
