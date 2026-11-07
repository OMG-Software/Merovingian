// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/secret_buffer.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

namespace merovingian::crypto
{

// Size of the libsodium Ed25519 secret key representation (seed || public key).
// Named so callers can size buffers without default-constructing an
// Ed25519Keypair purely to read `.secret_key.size()` — the secret is now a
// move-only SecretBuffer whose size is a runtime property.
constexpr auto ed25519_secret_key_bytes = std::size_t{64U};
constexpr auto ed25519_public_key_bytes = std::size_t{32U};

// The secret half lives in core::SecretBuffer, not a plain std::array: this is
// forgery-capable material, so it must be mlocked against swap and zeroised on
// destruction for its whole lifetime, including the window between generation
// and storage encoding. That makes the keypair move-only.
struct Ed25519Keypair final
{
    std::array<std::uint8_t, ed25519_public_key_bytes> public_key{};
    core::SecretBuffer secret_key{};
};

} // namespace merovingian::crypto
