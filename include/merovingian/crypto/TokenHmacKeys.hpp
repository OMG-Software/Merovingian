// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/TokenHmacKey.hpp"

#include <optional>

namespace merovingian::crypto
{

// Both access-token HMAC keys, derived together from one read of the master key.
struct TokenHmacKeys final
{
    std::optional<TokenHmacKey> v3{};
    std::optional<TokenHmacKey> v4{};
};

} // namespace merovingian::crypto
