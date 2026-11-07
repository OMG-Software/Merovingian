// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/OutboundError.hpp"

#include <cstdint>
#include <string>

namespace merovingian::identity
{

// Outcome of an Identity Service API call. `ok` reflects *transport* success
// only (DNS/TLS/SSRF/connection/timeout) — callers fail closed on `ok == false`
// and use `error`/`error_detail` for audit logging. When `ok` is true, `status`
// holds the IS HTTP status and `body` the raw response body; the caller branches
// on `status` for IS-level outcomes (e.g. a 404 on lookup means "no binding",
// not a transport failure).
struct IdentityServerResult final
{
    bool ok{false};
    std::uint16_t status{0U};
    std::string body{};
    http::OutboundError error{http::OutboundError::network_error};
    std::string error_detail{};
};

} // namespace merovingian::identity
