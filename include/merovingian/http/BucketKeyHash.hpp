// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/crypto/generic_hash.hpp"
#include "merovingian/crypto/random.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::http
{

// The rate limiter's own bucket tables are keyed by attacker-influenceable
// strings: the per-IP key is `client_ip|normalized_target` and the per-user key
// carries a user ID. `std::hash<std::string>` is neither collision-resistant nor
// randomised across processes, so an attacker can precompute a set of colliding
// keys once and reuse it against every deployment, collapsing the table into a
// linear scan. That turns the structure the server uses to *defend* against
// floods into the thing the flood attacks.
//
// The key is hashed with libsodium's keyed BLAKE2b through the crypto boundary
// (never libsodium directly — see src/crypto/AGENTS.md) under a per-process
// random key, so collisions cannot be precomputed offline and differ between
// processes. `kMaxBucketsPerTable` still bounds table size; this bounds the
// cost of each lookup within it.
struct BucketKeyHash final
{
    [[nodiscard]] static auto process_key() -> std::vector<std::uint8_t> const&
    {
        // One 32-byte key per process. If the RNG is unavailable the hash falls
        // back to unkeyed BLAKE2b, which is still collision-resistant — losing
        // the per-process unpredictability is acceptable; losing the hash is
        // not.
        static auto const key = crypto::secure_random_bytes(32U).value_or(std::vector<std::uint8_t>{});
        return key;
    }

    [[nodiscard]] auto operator()(std::string const& key) const -> std::size_t
    {
        auto const pieces = std::array<std::string_view, 1U>{std::string_view{key}};
        auto const digest = crypto::generic_hash_bytes(pieces, process_key());
        if (!digest.has_value() || digest->size() < sizeof(std::size_t))
        {
            return std::hash<std::string>{}(key);
        }
        auto value = std::size_t{0U};
        std::memcpy(&value, digest->data(), sizeof(value));
        return value;
    }
};

} // namespace merovingian::http
