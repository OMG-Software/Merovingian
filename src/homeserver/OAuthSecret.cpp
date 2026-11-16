// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#include "merovingian/homeserver/OAuthSecret.hpp"

#include "merovingian/crypto/GenericHash.hpp"
#include "merovingian/crypto/Random.hpp"

#include <array>

namespace merovingian::homeserver
{

auto make_oauth_secret() -> std::optional<std::string>
{
    return crypto::secure_random_hex(oauth_secret_bytes);
}

auto oauth_secret_hash(std::string_view secret) -> std::optional<std::string>
{
    auto const pieces = std::array<std::string_view, 1U>{secret};
    return crypto::generic_hash(pieces);
}

} // namespace merovingian::homeserver
