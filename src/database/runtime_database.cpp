// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/database/runtime_database.hpp>

#include <string>

namespace merovingian::database
{

auto make_runtime_database_config(config::Config const& config) -> RuntimeDatabaseConfig
{
    return {config.database().uri_file, config.database().pool_size};
}

auto database_summary(RuntimeDatabaseConfig const& config) -> std::string
{
    return "Database URI source file configured; pool_size=" + std::to_string(config.pool_size);
}

} // namespace merovingian::database
