// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::platform
{

// Outcome of attempting to add one path rule to a Landlock ruleset.
enum class LandlockAddRuleOutcome : std::uint8_t
{
    success,
    // The path could not be opened (commonly: it does not exist on this
    // host). Fatal only when the owning LandlockPathRule::required is true.
    path_unavailable,
    // The path opened, but the landlock_add_rule() syscall itself failed.
    // Always fatal, independent of `required` — this indicates the ruleset
    // or kernel state is broken, not that the path is merely absent.
    failed,
};

} // namespace merovingian::platform
