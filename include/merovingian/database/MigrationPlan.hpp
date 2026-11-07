// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/MigrationDirection.hpp"
#include "merovingian/database/MigrationStep.hpp"

#include <cstdint>
#include <vector>

namespace merovingian::database
{

struct MigrationPlan final
{
    std::uint32_t current_version{0U};
    std::uint32_t target_version{0U};
    std::vector<MigrationStep> steps{};
    MigrationDirection direction{MigrationDirection::upgrade};
};

} // namespace merovingian::database
