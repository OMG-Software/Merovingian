// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/constant_time.hpp"

#include <array>
#include <span>
#include <string_view>
#include <tuple>
#include <utility>

#include <sodium.h>

namespace merovingian::crypto
{
namespace
{

    // Domain-separated context string for the variable-length comparison hash.
    // The string itself is public; it guarantees this hash is never confused
    // with other generichash uses in the project.
    constexpr auto comparison_context = std::string_view{"merovingian:constant-time-compare:1"};

} // namespace

auto constant_time_equal(std::string_view left, std::string_view right) noexcept -> bool
{
    // Length is not secret here (token hashes and signatures are fixed-size),
    // so comparing sizes up front is safe. The equal-length byte comparison is
    // delegated to libsodium's sodium_memcmp — the hardened, optimisation-proof
    // constant-time primitive — rather than a hand-rolled loop the compiler
    // could legally short-circuit.
    if (left.size() != right.size())
    {
        return false;
    }
    return sodium_memcmp(left.data(), right.data(), left.size()) == 0;
}

auto constant_time_equal_variable_length(std::string_view left, std::string_view right) noexcept -> bool
{
    auto hash_one = [](std::string_view value) -> std::array<unsigned char, crypto_generichash_BYTES> {
        auto digest = std::array<unsigned char, crypto_generichash_BYTES>{};
        auto state = crypto_generichash_state{};
        if (crypto_generichash_init(&state, nullptr, 0U, crypto_generichash_BYTES) != 0)
        {
            return digest;
        }
        // Domain separation: prefix every input with the public context string so
        // the comparison digest cannot be confused with hashes produced elsewhere.
        std::ignore = crypto_generichash_update(
            &state, reinterpret_cast<unsigned char const*>(comparison_context.data()), comparison_context.size());
        std::ignore = crypto_generichash_update(&state, reinterpret_cast<unsigned char const*>(value.data()),
                                                static_cast<unsigned long long>(value.size()));
        std::ignore = crypto_generichash_final(&state, digest.data(), digest.size());
        return digest;
    };

    auto const left_digest = hash_one(left);
    auto const right_digest = hash_one(right);
    return sodium_memcmp(left_digest.data(), right_digest.data(), left_digest.size()) == 0;
}

} // namespace merovingian::crypto
