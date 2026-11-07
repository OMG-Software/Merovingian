// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/MigrationDirection.hpp"
#include "merovingian/database/PreparedStatement.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::database
{

struct MigrationStep final
{
    std::uint32_t version{0U};
    std::string name{};
    std::vector<PreparedStatement> statements{};
    MigrationDirection direction{MigrationDirection::upgrade};
};

} // namespace merovingian::database
