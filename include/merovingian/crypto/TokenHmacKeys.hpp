// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/TokenHmacKey.hpp"

#include <optional>

namespace merovingian::crypto
{

// Both access-token HMAC keys and the OAuth 2.0 client ID key, derived together from one read of the master key.
struct TokenHmacKeys final
{
    std::optional<TokenHmacKey> v3{};
    std::optional<TokenHmacKey> v4{};
    // The key of crypto::oauth_client_id (ADR-0779), never used to hash a token.
    std::optional<TokenHmacKey> oauth_client_id{};
};

} // namespace merovingian::crypto
