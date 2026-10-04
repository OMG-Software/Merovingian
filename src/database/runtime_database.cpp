// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/runtime_database.hpp"

#include <string>

namespace merovingian::database
{

auto make_runtime_database_config(config::Config const& config) -> RuntimeDatabaseConfig
{
    auto runtime = RuntimeDatabaseConfig{};
    runtime.backend = config.database().backend;
    runtime.uri_file = config.database().uri_file;
    runtime.sqlite_path = config.database().sqlite_path;
    runtime.pool_size = config.database().pool_size;
    runtime.role = config.database().role;
    runtime.warning = std::string{config::database_backend_performance_warning(config.database().backend)};
    return runtime;
}

auto database_summary(RuntimeDatabaseConfig const& config) -> std::string
{
    auto summary = std::string{};
    switch (config.backend)
    {
    case config::DatabaseBackend::memory:
        summary = "In-memory database selected";
        break;
    case config::DatabaseBackend::postgresql:
        summary = "Database URI source file configured";
        break;
    case config::DatabaseBackend::sqlite:
        summary = "Database SQLite path configured";
        break;
    }
    summary += "; pool_size=" + std::to_string(config.pool_size);
    summary += "; backend=" + std::string{config::database_backend_name(config.backend)};
    summary += "; role=" + std::string{config::database_role_name(config.role)};
    if (!config.warning.empty())
    {
        summary += "; warning=" + config.warning;
    }
    return summary;
}

} // namespace merovingian::database
