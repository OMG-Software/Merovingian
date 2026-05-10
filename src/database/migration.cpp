// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/database/migration.hpp>

#include <algorithm>

namespace merovingian::database
{

auto migration_step_is_valid(MigrationStep const& step) -> MigrationValidationResult
{
    if (step.version == 0U)
    {
        return {false, "migration version must be non-zero"};
    }
    if (!statement_name_is_valid(step.name))
    {
        return {false, "migration name is invalid"};
    }
    if (step.statements.empty())
    {
        return {false, "migration has no statements"};
    }

    for (auto const& statement : step.statements)
    {
        auto const validation = prepared_statement_is_valid(statement);
        if (!validation.valid)
        {
            return {false, "migration statement invalid: " + validation.reason};
        }
    }

    return {true, {}};
}

auto migration_plan_is_valid(MigrationPlan const& plan) -> MigrationValidationResult
{
    if (plan.target_version < plan.current_version)
    {
        return {false, "downgrade migrations are not allowed"};
    }
    if (plan.current_version == plan.target_version)
    {
        return plan.steps.empty() ? MigrationValidationResult{true, {}}
                                  : MigrationValidationResult{false, "no-op migration plan must not contain steps"};
    }
    if (plan.steps.empty())
    {
        return {false, "upgrade migration plan has no steps"};
    }

    auto expected_version = plan.current_version + 1U;
    for (auto const& step : plan.steps)
    {
        if (step.version != expected_version)
        {
            return {false, "migration versions must be contiguous"};
        }
        auto const validation = migration_step_is_valid(step);
        if (!validation.valid)
        {
            return validation;
        }
        ++expected_version;
    }

    if (plan.steps.back().version != plan.target_version)
    {
        return {false, "migration plan does not reach target version"};
    }

    return {true, {}};
}

auto migration_plan_summary(MigrationPlan const& plan) -> std::string
{
    return "database migration plan current_version=" + std::to_string(plan.current_version)
        + " target_version=" + std::to_string(plan.target_version) + " steps=" + std::to_string(plan.steps.size());
}

} // namespace merovingian::database
