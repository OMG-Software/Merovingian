// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/crypto/constant_time.hpp"

#include <sodium.h>

namespace merovingian::crypto
{

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

} // namespace merovingian::crypto
