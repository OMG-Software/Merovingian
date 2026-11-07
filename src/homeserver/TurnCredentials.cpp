// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/TurnCredentials.hpp"

#include "merovingian/crypto/encoding.hpp"
#include "merovingian/crypto/hmac_sha1.hpp"

#include <span>
#include <string>
#include <vector>

namespace merovingian::homeserver
{

auto make_turn_credentials(std::span<std::uint8_t const> secret, std::string_view user_id, std::uint64_t now_seconds,
                           std::uint32_t ttl_seconds) -> std::optional<TurnCredentials>
{
    auto username = std::to_string(now_seconds + ttl_seconds) + ":" + std::string{user_id};
    auto const message = std::vector<std::uint8_t>{username.begin(), username.end()};
    auto const mac = crypto::hmac_sha1(secret, message);
    if (!mac.has_value())
    {
        return std::nullopt;
    }
    auto const raw = std::string{mac->begin(), mac->end()};
    auto password = crypto::base64_original_encode(raw);
    if (!password.has_value())
    {
        return std::nullopt;
    }
    return TurnCredentials{std::move(username), std::move(*password)};
}

} // namespace merovingian::homeserver
