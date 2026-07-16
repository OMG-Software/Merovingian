// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/ipc_auth_key.hpp"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <span>

namespace merovingian::crypto
{

// AEAD-encrypted stream cipher for the federation-worker IPC channel.
//
// Wraps libsodium's crypto_kx + crypto_auth handshake and
// crypto_secretstream_xchacha20poly1305 frame encryption so that src/ipc/
// never calls libsodium directly (crypto-boundary rule, issue #396).  The
// implementation is hidden behind a pimpl so the sodium state types do not leak
// out of src/crypto/.
class IpcStreamCipher final
{
public:
    enum class Role : std::uint8_t
    {
        server, // sends the secretstream header first
        client, // receives the secretstream header first
    };

    // send_fn/recv_fn must transfer exactly the requested number of bytes and
    // return true only on complete success.  They are invoked synchronously from
    // the constructor while the crypto_kx handshake runs.
    explicit IpcStreamCipher(Role role, IpcAuthKey auth_key, std::function<bool(void const*, std::size_t)> send_fn,
                             std::function<bool(void*, std::size_t)> recv_fn);

    ~IpcStreamCipher();

    IpcStreamCipher(IpcStreamCipher const&) = delete;
    auto operator=(IpcStreamCipher const&) -> IpcStreamCipher& = delete;
    IpcStreamCipher(IpcStreamCipher&&) = delete;
    auto operator=(IpcStreamCipher&&) -> IpcStreamCipher& = delete;

    [[nodiscard]] auto ciphertext_size(std::size_t plaintext_size) const noexcept -> std::size_t;

    // Encrypt a plaintext frame into the caller-provided ciphertext buffer.
    // `ciphertext` must be exactly ciphertext_size(plaintext.size()) bytes.
    [[nodiscard]] auto encrypt(std::span<std::uint8_t const> plaintext, std::span<std::uint8_t> ciphertext) noexcept
        -> bool;

    // Decrypt a ciphertext frame into the caller-provided plaintext buffer.
    // `plaintext` must be exactly ciphertext.size() - ABYTES bytes.
    [[nodiscard]] auto decrypt(std::span<std::uint8_t const> ciphertext, std::span<char> plaintext) noexcept -> bool;

private:
    struct State;
    std::unique_ptr<State> state_;
};

} // namespace merovingian::crypto
