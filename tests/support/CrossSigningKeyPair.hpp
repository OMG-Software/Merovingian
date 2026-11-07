// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/SecretBuffer.hpp"

#include <string>

namespace merovingian::tests
{

struct CrossSigningKeyPair final
{
    std::string public_key{}; // unpadded base64, the key's ID without "ed25519:"
    core::SecretBuffer secret_key{};
};

} // namespace merovingian::tests
