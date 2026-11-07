// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

struct TurnCredentials final
{
    std::string username{};
    std::string password{};
};

// The coturn REST API credentials (`use-auth-secret`, ADR-0480): the username is `<expiry>:<user_id>`, where
// `expiry` is `now_seconds + ttl_seconds` as a Unix time, and the password is the standard base64 of
// HMAC-SHA1(secret, username). The TURN server recomputes the MAC from the username it is shown, so the credential
// needs no storage and ends at the expiry. nullopt for an empty secret or when the MAC cannot be made.
[[nodiscard]] auto make_turn_credentials(std::span<std::uint8_t const> secret, std::string_view user_id,
                                         std::uint64_t now_seconds, std::uint32_t ttl_seconds)
    -> std::optional<TurnCredentials>;

} // namespace merovingian::homeserver
