// SPDX-License-Identifier: GPL-3.0-or-later
//
// Linked only into the unit, conformance and integration binaries, with -Wl,--wrap=crypto_pwhash_str, so their calls
// to crypto_pwhash_str arrive here (ADR-0510). Nothing the server, the worker or a package links can reach this.
//
// The hash stays a real Argon2id hash of the password, and crypto_pwhash_str_verify takes its cost from the stored
// string, so verifying is cheap too and every check of a password still means what it means in production. Only the
// cost differs. A caller asking for any cost but production's is refused, so a downgrade in src/auth/Password.cpp
// cannot hide behind this: every registration and login in these binaries fails.

#include "RealPasswordHashCost.hpp"

#include <sodium.h>

#include <atomic>
#include <cerrno>
#include <cstddef>
#include <iostream>

// NOLINTBEGIN(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)
// These names and this C signature are what --wrap and libsodium define, so they cannot follow the project's rules
// on reserved identifiers and raw pointers.
extern "C"
{
    auto __real_crypto_pwhash_str(char out[crypto_pwhash_STRBYTES], char const* passwd, unsigned long long passwdlen,
                                  unsigned long long opslimit, std::size_t memlimit) -> int;
    auto __wrap_crypto_pwhash_str(char out[crypto_pwhash_STRBYTES], char const* passwd, unsigned long long passwdlen,
                                  unsigned long long opslimit, std::size_t memlimit) -> int;
}

namespace
{

// Scenarios run one at a time, but a scenario may hash on a thread it started.
std::atomic<int> real_cost_holders{0};

} // namespace

auto __wrap_crypto_pwhash_str(char out[crypto_pwhash_STRBYTES], char const* passwd, unsigned long long passwdlen,
                              unsigned long long opslimit, std::size_t memlimit) -> int
{
    if (opslimit != crypto_pwhash_OPSLIMIT_INTERACTIVE || memlimit != crypto_pwhash_MEMLIMIT_INTERACTIVE)
    {
        std::cerr << "password_hash_cost: refused crypto_pwhash_str at opslimit " << opslimit << ", memlimit "
                  << memlimit << ": production hashes at the interactive cost (ADR-0510)\n";
        errno = EINVAL;
        return -1;
    }
    if (real_cost_holders.load(std::memory_order_relaxed) > 0)
    {
        return __real_crypto_pwhash_str(out, passwd, passwdlen, opslimit, memlimit);
    }
    return crypto_pwhash_argon2id_str(out, passwd, passwdlen, crypto_pwhash_argon2id_OPSLIMIT_MIN,
                                      crypto_pwhash_argon2id_MEMLIMIT_MIN);
}
// NOLINTEND(bugprone-reserved-identifier,cert-dcl37-c,cert-dcl51-cpp)

namespace merovingian::tests
{

RealPasswordHashCost::RealPasswordHashCost() noexcept
{
    real_cost_holders.fetch_add(1, std::memory_order_relaxed);
}

RealPasswordHashCost::~RealPasswordHashCost()
{
    real_cost_holders.fetch_sub(1, std::memory_order_relaxed);
}

} // namespace merovingian::tests
