// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/MigrationStep.hpp"

#include <string>
#include <vector>

namespace merovingian::database
{

struct MigrationFileLoadResult final
{
    bool ok{false};
    std::string reason{};
    std::vector<MigrationStep> steps{};
};

} // namespace merovingian::database
