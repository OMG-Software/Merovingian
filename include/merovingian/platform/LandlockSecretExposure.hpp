// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::platform
{

// A Landlock rule that would grant the worker access to a configured secret.
struct LandlockSecretExposure final
{
    std::string rule_path;
    std::string secret_path;
};

} // namespace merovingian::platform
