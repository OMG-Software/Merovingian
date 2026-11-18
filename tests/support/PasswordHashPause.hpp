// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <chrono>

namespace merovingian::tests
{

// While one lives, the next crypto_pwhash_str call, on any thread, stops inside the hash until release() or the
// pause's destruction. Production hashes a password only inside a RuntimeLockRelease scope, so once
// wait_until_hashing() returns true the hashing request holds no runtime lock, and the scenario can make its
// competing request at exactly that point instead of hoping it lands inside the hash (ADR-0851). Only the
// unit, conformance and integration binaries route crypto_pwhash_str here (RealPasswordHashCost.cpp,
// ADR-0510). Arm it after the scenario's own setup has hashed what it needs: the first hash after arming stops.
class PasswordHashPause
{
public:
    PasswordHashPause() noexcept;
    ~PasswordHashPause();

    PasswordHashPause(PasswordHashPause const&) = delete;
    auto operator=(PasswordHashPause const&) -> PasswordHashPause& = delete;
    PasswordHashPause(PasswordHashPause&&) = delete;
    auto operator=(PasswordHashPause&&) -> PasswordHashPause& = delete;

    // True once a hash has stopped here, false when none has within `timeout`.
    [[nodiscard]] auto wait_until_hashing(std::chrono::milliseconds timeout) const -> bool;
    // Lets the stopped hash finish (and any later one run). Safe to call more than once.
    void release() const;
};

namespace detail
{

    // Called by the crypto_pwhash_str wrapper on every hash: stops the first hash after a PasswordHashPause is armed.
    void pause_password_hash_if_armed();

} // namespace detail

} // namespace merovingian::tests
