// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/secret_box.hpp"

#include <sodium.h>

#include <algorithm>
#include <string>

namespace merovingian::crypto
{
namespace
{

    [[nodiscard]] auto sodium_is_ready() noexcept -> bool
    {
        static auto const ready = sodium_init() >= 0;
        return ready;
    }

    // Domain separation label for deriving the signing-secret encryption key
    // from the operator's master key material.  Prevents the same master key
    // from being reused for unrelated symmetric encryption in the project.
    constexpr auto k_context = std::string_view{"merovingian:signing-secret:1"};

} // namespace

auto derive_secret_box_key(std::span<std::uint8_t const> master_key_material) noexcept -> std::optional<SecretBoxKey>
{
    if (!sodium_is_ready() || master_key_material.empty())
    {
        return std::nullopt;
    }

    auto key = SecretBoxKey{};
    if (crypto_generichash(key.bytes.data(), key.bytes.size(), master_key_material.data(),
                           master_key_material.size(), reinterpret_cast<unsigned char const*>(k_context.data()),
                           k_context.size())
        != 0)
    {
        return std::nullopt;
    }
    return key;
}

auto secret_box_encrypt(std::span<std::uint8_t const> plaintext, SecretBoxKey const& key)
    -> std::optional<SecretBoxCiphertext>
{
    if (!sodium_is_ready() || plaintext.empty())
    {
        return std::nullopt;
    }

    auto nonce = std::array<std::uint8_t, crypto_secretbox_NONCEBYTES>{};
    randombytes_buf(nonce.data(), nonce.size());

    auto ciphertext = SecretBoxCiphertext{};
    ciphertext.bytes.resize(crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES + plaintext.size());

    std::copy_n(nonce.begin(), crypto_secretbox_NONCEBYTES, ciphertext.bytes.begin());

    if (crypto_secretbox_easy(ciphertext.bytes.data() + crypto_secretbox_NONCEBYTES, plaintext.data(),
                              plaintext.size(), nonce.data(), key.bytes.data())
        != 0)
    {
        return std::nullopt;
    }

    return ciphertext;
}

auto secret_box_decrypt(SecretBoxCiphertext const& ciphertext, SecretBoxKey const& key)
    -> std::optional<std::vector<std::uint8_t>>
{
    auto const min_size = crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES;
    if (!sodium_is_ready() || ciphertext.bytes.size() < min_size)
    {
        return std::nullopt;
    }

    auto const nonce = ciphertext.bytes.data();
    auto const encrypted = ciphertext.bytes.data() + crypto_secretbox_NONCEBYTES;
    auto const encrypted_size = ciphertext.bytes.size() - crypto_secretbox_NONCEBYTES;

    auto plaintext = std::vector<std::uint8_t>(encrypted_size - crypto_secretbox_MACBYTES);

    if (crypto_secretbox_open_easy(plaintext.data(), encrypted, encrypted_size, nonce, key.bytes.data()) != 0)
    {
        return std::nullopt;
    }

    return plaintext;
}

} // namespace merovingian::crypto
