// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstddef>

namespace merovingian::auth
{

// The rule a password a person chooses must meet (security.password_policy,
// ADR-0236). The defaults are the rule the server enforced before it was
// configurable: at least 12 bytes, with a lower-case and an upper-case ASCII
// letter, an ASCII digit and an ASCII symbol. An empty password never passes.
struct PasswordPolicy final
{
    std::size_t min_length{12U};
    bool require_character_classes{true};
};

} // namespace merovingian::auth
