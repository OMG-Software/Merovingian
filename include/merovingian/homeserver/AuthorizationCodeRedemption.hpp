// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/AuthorizationGrant.hpp"

#include <cstdint>
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
        // A live code already redeemed once: `user_id` and `device_id` name the session the first redemption was for,
        // so the token endpoint can revoke it ("a code presented twice revokes the session it produced"). `grant` is
        // empty.
        replayed,
        // No live code has this value: never minted, expired, or the hash failed. Nothing else is set.
        unknown,
    };

    Outcome outcome{Outcome::unknown};
    AuthorizationGrant grant{};
    std::string user_id{};
    std::string device_id{};
};

} // namespace merovingian::homeserver
