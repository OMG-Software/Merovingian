// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::platform
{

// Result of apply_worker_landlock().
struct LandlockHardeningResult final
{
    // True when the worker may proceed: either the ruleset was applied, or
    // Landlock is unavailable on this kernel and the operator explicitly
    // opted out via federation.worker.allow_without_landlock=true.
    bool accepted{false};
    // True only when landlock_restrict_self() actually installed the
    // ruleset. False whenever `accepted` is true solely because of the
    // unavailable+opt-out path below.
    bool applied{false};
    // True when this start must be logged CRITICAL: Landlock is unavailable
    // and the operator opted out. The caller must log this on EVERY such
    // start, not just the first — mirroring ADR-0041's fail-closed seccomp
    // policy for the worker.
    bool critical_warning{false};
    std::string reason{};
};

} // namespace merovingian::platform
