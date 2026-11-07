// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <vector>

namespace merovingian::crypto
{

// Nonce + XSalsa20-Poly1305 ciphertext, stored as raw bytes (caller encodes
// to base64 or another printable form).
struct SecretBoxCiphertext final
{
    std::vector<std::uint8_t> bytes{}; // nonce || mac || ciphertext
};

} // namespace merovingian::crypto
