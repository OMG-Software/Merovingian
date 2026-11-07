// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/Config.hpp"
#include "merovingian/config/ConfigValidationFinding.hpp"

#include <vector>

namespace merovingian::config
{

struct ConfigParseResult final
{
    Config config{};
    std::vector<ConfigValidationFinding> findings{};
};

} // namespace merovingian::config
