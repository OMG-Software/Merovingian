// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/MigrationDirection.hpp"

#include <cstdint>
#include <string>

namespace merovingian::database
{

struct MigrationRecord final
{
    std::uint32_t version{0U};
    std::string name{};
    MigrationDirection direction{MigrationDirection::upgrade};
};

} // namespace merovingian::database
