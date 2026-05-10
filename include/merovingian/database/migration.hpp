// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <merovingian/database/statement.hpp>

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::database
{

struct MigrationStep final
{
    std::uint32_t version{0U};
    std::string name{};
    std::vector<PreparedStatement> statements{};
};

struct MigrationPlan final
{
    std::uint32_t current_version{0U};
    std::uint32_t target_version{0U};
    std::vector<MigrationStep> steps{};
};

struct MigrationValidationResult final
{
    bool valid{false};
    std::string reason{};
};

[[nodiscard]] auto migration_step_is_valid(MigrationStep const& step) -> MigrationValidationResult;
[[nodiscard]] auto migration_plan_is_valid(MigrationPlan const& plan) -> MigrationValidationResult;
[[nodiscard]] auto migration_plan_summary(MigrationPlan const& plan) -> std::string;

} // namespace merovingian::database
