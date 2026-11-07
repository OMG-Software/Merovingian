// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::homeserver
{

// Outcome of an `/_merovingian/admin/*` auth gate. `user_id` is set when the
// presented token belongs to a confirmed admin; otherwise `denial` identifies
// which HTTP response applies — `missing_token` for a missing/expired/unknown
// token (401 M_MISSING_TOKEN/M_UNKNOWN_TOKEN) and `not_admin` for a valid
// token whose user is not an admin (403 M_FORBIDDEN). This splits the two
// cases `authenticated_admin_user` collapses, so admin routes match the
// `/_matrix/client/v3/admin/*` status-code convention (spec v1.19).
struct AdminAuthResult
{
    enum class Denial : std::uint8_t
    {
        none,
        missing_token,
        not_admin,
    };
    std::optional<std::string> user_id{};
    Denial denial{Denial::none};
};

} // namespace merovingian::homeserver
