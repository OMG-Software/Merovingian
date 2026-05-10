// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <merovingian/database/statement.hpp>

#include <cstdint>
#include <string>
#include <string_view>
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

struct MigrationRecord final
{
    std::uint32_t version{0U};
    std::string name{};
};

struct SchemaState final
{
    std::uint32_t version{0U};
    std::vector<std::string> tables{};
    std::vector<MigrationRecord> applied_migrations{};
};

struct MigrationApplyResult final
{
    bool ok{false};
    std::string reason{};
    SchemaState state{};
};

[[nodiscard]] auto migration_step_is_valid(MigrationStep const& step) -> MigrationValidationResult;
[[nodiscard]] auto migration_plan_is_valid(MigrationPlan const& plan) -> MigrationValidationResult;
[[nodiscard]] auto migration_plan_summary(MigrationPlan const& plan) -> std::string;
[[nodiscard]] auto initial_schema_migration() -> MigrationStep;
[[nodiscard]] auto migration_plan_for(SchemaState const& state) -> MigrationPlan;
[[nodiscard]] auto apply_migration_plan(SchemaState state, MigrationPlan const& plan) -> MigrationApplyResult;
[[nodiscard]] auto schema_state_is_compatible(SchemaState const& state) -> MigrationValidationResult;
[[nodiscard]] auto migration_rollback_policy() noexcept -> std::string_view;

} // namespace merovingian::database
