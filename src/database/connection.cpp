// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/connection.hpp"

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
