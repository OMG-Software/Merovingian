// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PostgresqlConnection.hpp"

#include <string>

namespace merovingian::database
{

struct PostgresqlConnectionOpenResult final
{
    bool ok{false};
    std::string reason{};
    std::string redacted_conninfo{};
    PostgresqlConnection connection{};
};

} // namespace merovingian::database
