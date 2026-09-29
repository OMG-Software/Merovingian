// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstddef>
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
// Secret material must not survive past its scope (core/AGENTS.md): the
// destructor zeroises `bytes` with sodium_memzero, and copies/moves zeroise
// whichever instance is left behind rather than relying on the caller.
struct IpcAuthKey final
{
    std::array<unsigned char, crypto_auth_KEYBYTES> bytes{};

    IpcAuthKey() noexcept = default;
    IpcAuthKey(IpcAuthKey const& other) noexcept;
    auto operator=(IpcAuthKey const& other) noexcept -> IpcAuthKey&;
    IpcAuthKey(IpcAuthKey&& other) noexcept;
    auto operator=(IpcAuthKey&& other) noexcept -> IpcAuthKey&;
    ~IpcAuthKey();
};

// Size in bytes of an IpcAuthKey (== crypto_auth_KEYBYTES), exposed as a plain
// std::size_t so callers that must not include <sodium.h> themselves (e.g.
// src/federation_worker/, which is outside the crypto-boundary allowlist) can
// size a buffer for the key without depending on the libsodium macro.
inline constexpr std::size_t kIpcAuthKeyBytes{crypto_auth_KEYBYTES};

// Derive an independent IPC channel auth key from master key material using a
// domain-separated libsodium generic hash. The label is distinct from the
// access-token HMAC labels so the keys can never collide across purposes. The
// same input material always produces the same derived key, so both processes
// derive an identical key independently. Returns nullopt if libsodium is not
// initialised or the material is empty.
[[nodiscard]] auto derive_ipc_auth_key(std::span<std::uint8_t const> master_key_material) noexcept
    -> std::optional<IpcAuthKey>;

// Wraps already-derived key material into an IpcAuthKey value without
// re-hashing it. Used on both ends of a key handoff that happens after
// derive_ipc_auth_key has already run once: main packages its own derived key
// for the worker's inherited key-fd (WorkerSupervisor::spawn_and_connect), and
// the worker rebuilds the same value from the bytes it reads back off that fd
// (federation_worker::read_ipc_auth_key). Returns nullopt if key_bytes.size()
// != kIpcAuthKeyBytes, so a short or long read is rejected by the same check
// rather than silently truncated or padded.
[[nodiscard]] auto ipc_auth_key_from_bytes(std::span<std::uint8_t const> key_bytes) noexcept
    -> std::optional<IpcAuthKey>;

} // namespace merovingian::crypto