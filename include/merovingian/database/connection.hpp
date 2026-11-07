// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/DatabaseExecutor.hpp"
#include "merovingian/database/QueryResult.hpp"
#include "merovingian/database/statement.hpp"

namespace merovingian::database
{

[[nodiscard]] auto execute_validated(DatabaseExecutor& executor, PreparedStatement const& statement) -> QueryResult;

} // namespace merovingian::database
