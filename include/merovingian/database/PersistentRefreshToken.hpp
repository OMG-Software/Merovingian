// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>
#include <optional>
#include <string>

namespace merovingian::database
{

struct PersistentRefreshToken final
{
    std::string user_id{};
    std::string device_id{};
    std::string token_hash{};
    bool revoked{false};
    std::optional<std::chrono::system_clock::time_point> expires_at{};
    // For a refresh token minted by POST /refresh: the hash of the refresh
    // token it replaces, which stays valid until this pair is first used
    // (ADR-0074). Empty for tokens minted at login.
    std::string predecessor_hash{};
};

} // namespace merovingian::database
