// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::database
{

// A stored server signing-key row.
//
// `secret_key` holds the at-rest form of this server's own Ed25519 signing
// secret: since 0.12.5 always `secretbox:v1:<base64>` ciphertext, and for a row
// written by an older release possibly legacy plaintext base64.
//
// 0.12.5 audit, finding 17: it is a std::string, so the in-memory persistent
// store held that material in unpinned heap memory that was freed without being
// wiped -- and a std::string reallocating (or a row being copied out of the
// store's vector) left further unwiped copies behind. The field cannot become a
// core::SecretBuffer without making the whole row move-only, which the store's
// row vectors and every query path depend on not being; so instead the row
// zeroises the field itself. Copies each wipe their own buffer, and a move
// wipes what it leaves behind, so no path drops a secret without erasing it.
//
// This is a mitigation, not the guarantee SecretBuffer gives: the bytes are
// still swappable while live. What actually keeps them safe at rest is that
// they are ciphertext -- see finding 1 and crypto::signing_secret_box_key.
struct PersistentServerSigningKey final
{
    std::string server_name{};
    std::string key_id{};
    std::string public_key{};
    std::uint64_t valid_until_ts{0U};
    std::string secret_key{}; // at-rest ciphertext (legacy rows: plaintext base64)
    // Non-zero for a key a remote server published under old_verify_keys: the time it stopped using it.
    // Retirement is one way and the earliest expiry wins (store_server_signing_key); `valid_until_ts` of
    // such a row equals this. Never set on a row that holds a secret: this server's own keys.
    std::uint64_t expired_ts{0U};

    PersistentServerSigningKey() = default;
    PersistentServerSigningKey(std::string server_name_value, std::string key_id_value, std::string public_key_value,
                               std::uint64_t valid_until_ts_value, std::string secret_key_value = {});
    PersistentServerSigningKey(PersistentServerSigningKey const& other);
    auto operator=(PersistentServerSigningKey const& other) -> PersistentServerSigningKey&;
    PersistentServerSigningKey(PersistentServerSigningKey&& other) noexcept;
    auto operator=(PersistentServerSigningKey&& other) noexcept -> PersistentServerSigningKey&;
    ~PersistentServerSigningKey();
};

} // namespace merovingian::database
