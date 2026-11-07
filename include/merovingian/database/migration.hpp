// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/MigrationApplyResult.hpp"
#include "merovingian/database/MigrationDirection.hpp"
#include "merovingian/database/MigrationPlan.hpp"
#include "merovingian/database/MigrationStep.hpp"
#include "merovingian/database/MigrationValidationResult.hpp"
#include "merovingian/database/SchemaState.hpp"

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::database
{

[[nodiscard]] auto migration_direction_name(MigrationDirection direction) noexcept -> std::string_view;
[[nodiscard]] auto migration_step_is_valid(MigrationStep const& step) -> MigrationValidationResult;
[[nodiscard]] auto migration_plan_is_valid(MigrationPlan const& plan) -> MigrationValidationResult;
[[nodiscard]] auto migration_plan_summary(MigrationPlan const& plan) -> std::string;
[[nodiscard]] auto initial_schema_migration() -> MigrationStep;
[[nodiscard]] auto downgrade_initial_schema_migration() -> MigrationStep;
[[nodiscard]] auto upgrade_migration_catalog() -> std::vector<MigrationStep>;
[[nodiscard]] auto downgrade_migration_catalog() -> std::vector<MigrationStep>;
[[nodiscard]] auto migration_plan_for(SchemaState const& state) -> MigrationPlan;
[[nodiscard]] auto migration_plan_between(std::uint32_t current_version, std::uint32_t target_version) -> MigrationPlan;
[[nodiscard]] auto apply_migration_plan(SchemaState state, MigrationPlan const& plan) -> MigrationApplyResult;
// Refuses a ledger with an upgrade row that does not name this build's step at
// that version, such as one a pre-1.0 build wrote before the v1 collapse.
[[nodiscard]] auto schema_ledger_is_known(SchemaState const& state) -> MigrationValidationResult;
[[nodiscard]] auto schema_state_is_compatible(SchemaState const& state) -> MigrationValidationResult;
[[nodiscard]] auto migration_rollback_policy() noexcept -> std::string_view;

} // namespace merovingian::database
