// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/federation_worker/WorkerDatabaseConfig.hpp"

#include "merovingian/config/DatabaseBackend.hpp"

namespace merovingian::federation_worker
{

auto clear_database_location(config::Config& config) noexcept -> void
{
    auto& database = config.database();
    database.backend = config::DatabaseBackend::memory;
    database.sqlite_path.clear();
    database.uri_file.clear();
    database.migration_role.clear();
    database.runtime_role.clear();
}

} // namespace merovingian::federation_worker
