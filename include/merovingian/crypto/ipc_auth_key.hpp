// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>

#include <sodium.h>

namespace merovingian::crypto
{

// 32-byte symmetric key derived from the operator master key material, used to
// authenticate the federation-worker IPC crypto_kx handshake. Both the main
// process and the worker derive the same key from the same master key file and
// MAC each other's ephemeral KX public keys with it, so only a peer that can
// read the master key file can complete the handshake. crypto_kx provides
// confidentiality only; this key adds mutual authentication.
struct IpcAuthKey final
{
    std::array<unsigned char, crypto_auth_KEYBYTES> bytes{};
};

// Derive an independent IPC channel auth key from master key material using a
// domain-separated libsodium generic hash. The label is distinct from the
// access-token HMAC labels so the keys can never collide across purposes. The
// same input material always produces the same derived key, so both processes
// derive an identical key independently. Returns nullopt if libsodium is not
// initialised or the material is empty.
[[nodiscard]] auto derive_ipc_auth_key(std::span<std::uint8_t const> master_key_material) noexcept
    -> std::optional<IpcAuthKey>;

} // namespace merovingian::crypto