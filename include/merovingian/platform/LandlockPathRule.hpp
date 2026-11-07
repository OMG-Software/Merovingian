// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/platform/LandlockAccess.hpp"

#include <string>

namespace merovingian::platform
{

// One path the worker's Landlock ruleset grants `access` on.
struct LandlockPathRule final
{
    std::string path;
    LandlockAccess access{LandlockAccess::read_only};
    // When true, failing to add this rule (including the path not existing
    // on this host) is always fatal — see apply_worker_landlock(). Set this
    // for paths the worker cannot function correctly without, such as a
    // config-derived database directory. Best-effort system-integration
    // paths whose presence varies by distribution (CA bundle candidates, NSS
    // configuration files, library directories) should be `false`: a missing
    // optional path is logged and skipped rather than refusing to start.
    bool required{true};
};

} // namespace merovingian::platform
