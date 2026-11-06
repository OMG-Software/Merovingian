// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::config
{

// ADR-0236: the rule a password a person chooses must meet, at registration and
// on a password change. The defaults are the rule enforced before it was
// configurable. Anything weaker is logged at CRITICAL on every start, and a
// change needs a restart. Appservice users' generated credentials are exempt.
struct PasswordPolicyConfig final
{
    // Bytes, 1 to 1024.
    std::uint32_t min_length{12U};
    // A lower-case and an upper-case ASCII letter, an ASCII digit and an ASCII symbol.
    bool require_character_classes{true};
};

} // namespace merovingian::config
