// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"

namespace merovingian::tests
{

// Select the process-local database explicitly for tests that do not exercise
// persistence. Production config parsing intentionally does not expose this
// backend.
[[nodiscard]] inline auto in_memory_database_config() -> config::DatabaseConfig
{
    auto database = config::DatabaseConfig{};
    database.backend = config::DatabaseBackend::memory;
    database.uri_file.clear();
    database.sqlite_path.clear();
    return database;
}

} // namespace merovingian::tests
