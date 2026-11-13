// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <array>
#include <cstdint>

namespace merovingian::database
{

// An order-independent digest of the sessions of one key backup version (run-3 C22, ADR-0673): the number of sessions and
// the sum, limb by limb modulo 2^64, of a BLAKE2b hash of each session. Adding or removing a session changes it by that
// session's hash alone, so the backup's etag is read in constant time instead of being rehashed from every stored byte.
struct KeyBackupDigest final
{
    std::uint64_t count{0U};
    std::array<std::uint64_t, 4U> sum{};
};

} // namespace merovingian::database
