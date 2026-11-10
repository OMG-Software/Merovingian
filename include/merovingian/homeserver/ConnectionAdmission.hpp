// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/http/ConnectionLimiter.hpp"

#include <optional>
#include <string>

namespace merovingian::homeserver
{

// Whether an accepted connection may be served, and what it holds if so
// (ADR-0072, ADR-0077).
struct ConnectionAdmission final
{
    bool admitted{false};
    std::optional<http::ConnectionLimiter::Slot> slot{};
    // The per-client worker-share key (ADR-0077); empty when exempt.
    std::string client_key{};
};

} // namespace merovingian::homeserver
