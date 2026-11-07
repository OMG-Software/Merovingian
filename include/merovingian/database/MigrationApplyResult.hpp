// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/SchemaState.hpp"

#include <string>

namespace merovingian::database
{

struct MigrationApplyResult final
{
    bool ok{false};
    std::string reason{};
    SchemaState state{};
};

} // namespace merovingian::database
