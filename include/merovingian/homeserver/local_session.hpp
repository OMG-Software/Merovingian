// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <optional>
#include <string>

namespace merovingian::homeserver
{

struct LocalSession final
{
    std::string user_id{};
    std::string device_id{};
    std::string access_token_hash{};
    bool revoked{false};
    // Server-side access-token expiry mirrored from PersistentAccessToken. nullopt
    // = no expiry. find_session rejects an expired session even when not revoked.
    std::optional<std::chrono::system_clock::time_point> expires_at{};
    // Mirrored from PersistentAccessToken: the refresh token this access token
    // replaced. Its first successful use revokes that refresh token and clears
    // this field (ADR-0074).
    std::string predecessor_refresh_hash{};
};

} // namespace merovingian::homeserver
