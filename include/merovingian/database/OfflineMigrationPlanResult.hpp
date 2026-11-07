// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/MigrationPlan.hpp"

#include <string>

namespace merovingian::database
{

struct OfflineMigrationPlanResult final
{
    bool ok{false};
    std::string reason{};
    MigrationPlan plan{};
};

} // namespace merovingian::database
