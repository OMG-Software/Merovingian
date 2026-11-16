// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/AuthorizationGrant.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::homeserver
{

// What `AuthorizationCodeStore::redeem` found for a presented code.
struct AuthorizationCodeRedemption final
{
    enum class Outcome : std::uint8_t
    {
        // The first redemption of a live code: `grant` holds what it stands for, and the code is now spent.
        fresh,
        // A live code already redeemed once: `user_id`, `device_id` and `client_id` name the session the first
        // redemption was for, and `session_created_at_ms` is set when that redemption issued one (recorded with
        // `AuthorizationCodeStore::record_issued_session`), so the token endpoint can revoke it ("a code presented
        // twice revokes the session it produced") and only it (ADR-0792). `grant` is empty.
        replayed,
        // No live code has this value: never minted, expired, or the hash failed. Nothing else is set.
        unknown,
    };

    Outcome outcome{Outcome::unknown};
    AuthorizationGrant grant{};
    std::string user_id{};
    std::string device_id{};
    std::string client_id{};
    // `replayed` only: the `created_at_ms` of the `oauth_sessions` row the first redemption wrote, or nullopt when it
    // wrote none (the grant was refused or failed).
    std::optional<std::uint64_t> session_created_at_ms{};
};

} // namespace merovingian::homeserver
