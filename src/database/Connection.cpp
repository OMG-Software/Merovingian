// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/Connection.hpp"

#include "merovingian/database/DatabaseExecutor.hpp"
#include "merovingian/database/QueryResult.hpp"

namespace merovingian::database
{

auto execute_validated(DatabaseExecutor& executor, PreparedStatement const& statement) -> QueryResult
{
    auto const validation = prepared_statement_is_valid(statement);
    if (!validation.valid)
    {
        return {false, validation.reason, {}};
    }

    return executor.execute(statement);
}

} // namespace merovingian::database
