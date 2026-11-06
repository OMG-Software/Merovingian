// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/outbound_client.hpp"

#include <cstdint>
#include <string>

namespace merovingian::appservice
{

// Outcome of a `GET /_matrix/app/v1/users/{userId}` or
// `GET /_matrix/app/v1/rooms/{roomAlias}` query. `exists` reflects the
// spec's contract exactly: true only on HTTP 200 ("this user/alias exists");
// false on 404 ("does not exist"); `ok` is false only for a transport
// failure or an unexpected status (401/403/5xx), which the caller must NOT
// treat as a negative existence answer.
struct AppserviceQueryResult final
{
    bool ok{false};
    bool disabled{false};
    std::uint16_t status{0U};
    bool exists{false};
    http::OutboundError error{http::OutboundError::none};
    std::string error_detail{};
};

} // namespace merovingian::appservice
