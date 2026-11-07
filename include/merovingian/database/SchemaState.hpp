// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/MigrationRecord.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::database
{

struct SchemaState final
{
    std::uint32_t version{0U};
    std::vector<std::string> tables{};
    std::vector<MigrationRecord> applied_migrations{};
};

} // namespace merovingian::database
