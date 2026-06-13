// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"
#include "merovingian/database/migration.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::database
{

struct MigrationFileLoadResult final
{
    bool ok{false};
    std::string reason{};
    std::vector<MigrationStep> steps{};
};

struct OfflineMigrationPlanResult final
{
    bool ok{false};
    std::string reason{};
    MigrationPlan plan{};
};

[[nodiscard]] auto load_migration_files(std::string const& directory) -> MigrationFileLoadResult;
[[nodiscard]] auto build_offline_migration_plan(config::DatabaseConfig const& database_config,
                                                std::uint32_t current_version, std::uint32_t target_version,
                                                std::vector<MigrationStep> const& file_steps)
    -> OfflineMigrationPlanResult;
[[nodiscard]] auto offline_migrator_summary(OfflineMigrationPlanResult const& result) -> std::string;

} // namespace merovingian::database
