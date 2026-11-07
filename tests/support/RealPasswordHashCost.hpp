// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::tests
{

// The unit, conformance and integration binaries hash passwords at libsodium's minimum Argon2id cost
// (RealPasswordHashCost.cpp, ADR-0510). Holding this makes them hash at the real cost for as long as it lives,
// for a scenario that needs the hash to take real time: one that races another request against the window in
// which the runtime lock is released around Argon2id. Hold it from the start of the scenario, because verifying
// a password costs whatever the stored hash was made with.
class RealPasswordHashCost
{
public:
    RealPasswordHashCost() noexcept;
    ~RealPasswordHashCost();

    RealPasswordHashCost(RealPasswordHashCost const&) = delete;
    auto operator=(RealPasswordHashCost const&) -> RealPasswordHashCost& = delete;
    RealPasswordHashCost(RealPasswordHashCost&&) = delete;
    auto operator=(RealPasswordHashCost&&) -> RealPasswordHashCost& = delete;
};

} // namespace merovingian::tests
