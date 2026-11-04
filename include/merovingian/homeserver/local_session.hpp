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

// True when the session can never authenticate again: revoked is one-way (ADR-0052) and a finite expiry only
// moves further into the past. A session that expired less than `grace` ago is kept, so that the "token
// expired" audit reason survives for a while after the expiry.
[[nodiscard]] auto session_is_unusable(LocalSession const& session, std::chrono::system_clock::time_point now,
                                       std::chrono::system_clock::duration grace) noexcept -> bool;

} // namespace merovingian::homeserver
