// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <optional>
#include <string>

namespace merovingian::database
{

struct PersistentAccessToken final
{
    std::string user_id{};
    std::string device_id{};
    std::string token_hash{};
    bool revoked{false};
    // Server-side expiry. nullopt = no expiry (legacy rows / unset). Enforced by
    // find_session and the refresh-token lookup so an expired token is rejected
    // even when not revoked, forcing the refresh/re-login flow.
    std::optional<std::chrono::system_clock::time_point> expires_at{};
    // For an access token minted by POST /refresh: the hash of the refresh
    // token that was presented. Its first use revokes that refresh token
    // (ADR-0074). Empty for tokens minted any other way.
    std::string predecessor_refresh_hash{};
};

} // namespace merovingian::database
