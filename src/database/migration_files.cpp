// SPDX-License-Identifier: GPL-3.0-or-later

#include <algorithm>
#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <string_view>
#include <utility>

#include <merovingian/database/migration_files.hpp>

namespace merovingian::database
{
namespace
{

    [[nodiscard]] auto trim(std::string_view value) noexcept -> std::string_view
    {
        auto begin = std::size_t{0U};
        auto end = value.size();
        while (begin < end && (value[begin] == ' ' || value[begin] == '\t' || value[begin] == '\r'))
        {
            ++begin;
        }
        while (end > begin && (value[end - 1U] == ' ' || value[end - 1U] == '\t' || value[end - 1U] == '\r'))
        {
            --end;
        }
        return value.substr(begin, end - begin);
    }

    [[nodiscard]] auto token_value(std::string_view line, std::string_view key) -> std::string
    {
        auto const key_begin = line.find(key);
        if (key_begin == std::string_view::npos)
        {
            return {};
        }
        auto const value_begin = key_begin + key.size();
        auto const value_end = line.find(' ', value_begin);
        auto value = line.substr(value_begin, value_end == std::string_view::npos ? line.size() - value_begin
                                                                                  : value_end - value_begin);
        return std::string{trim(value)};
    }

    [[nodiscard]] auto parse_u32(std::string_view value) noexcept -> std::uint32_t
    {
        auto result = std::uint32_t{0U};
        for (auto const character : value)
        {
            if (character < '0' || character > '9')
            {
                return 0U;
            }
            result = (result * 10U) + static_cast<std::uint32_t>(character - '0');
        }
        return result;
    }

    [[nodiscard]] auto parse_direction(std::string_view value) noexcept -> MigrationDirection
    {
        return value == "downgrade" ? MigrationDirection::downgrade : MigrationDirection::upgrade;
    }

    [[nodiscard]] auto load_single_migration_file(std::filesystem::path const& path) -> MigrationFileLoadResult
    {
        auto input = std::ifstream{path};
        if (!input.is_open())
        {
            return {false, "unable to open migration file: " + path.string(), {}};
        }

        auto step = MigrationStep{};
        auto current_statement_name = std::string{};
        auto current_sql = std::string{};
        auto first_metadata_seen = false;
        auto line = std::string{};
        while (std::getline(input, line))
        {
            auto const trimmed = trim(line);
            if (trimmed.empty())
            {
                continue;
            }

            auto constexpr metadata_prefix = std::string_view{"-- merovingian-migration "};
            auto constexpr statement_prefix = std::string_view{"-- statement "};
            if (trimmed.starts_with(metadata_prefix))
            {
                auto const metadata = trimmed.substr(metadata_prefix.size());
                step.version = parse_u32(token_value(metadata, "version="));
                step.name = token_value(metadata, "name=");
                step.direction = parse_direction(token_value(metadata, "direction="));
                first_metadata_seen = true;
                continue;
            }
            if (trimmed.starts_with(statement_prefix))
            {
                if (!current_statement_name.empty())
                {
                    step.statements.push_back({std::move(current_statement_name), std::move(current_sql), {}});
                    current_sql.clear();
                }
                current_statement_name = std::string{trim(trimmed.substr(statement_prefix.size()))};
                continue;
            }
            if (!current_sql.empty())
            {
                current_sql.push_back(' ');
            }
            current_sql += trimmed;
        }
        if (!current_statement_name.empty())
        {
            step.statements.push_back({std::move(current_statement_name), std::move(current_sql), {}});
        }
        if (!first_metadata_seen)
        {
            return {false, "migration metadata is missing: " + path.string(), {}};
        }
        auto const validation = migration_step_is_valid(step);
        if (!validation.valid)
        {
            return {false, validation.reason, {}};
        }
        return {true, {}, {std::move(step)}};
    }

} // namespace

auto load_migration_files(std::string const& directory) -> MigrationFileLoadResult
{
    auto steps = std::vector<MigrationStep>{};
    auto paths = std::vector<std::filesystem::path>{};
    try
    {
        for (auto const& entry : std::filesystem::directory_iterator{directory})
        {
            if (entry.is_regular_file() && entry.path().extension() == ".sql")
            {
                paths.push_back(entry.path());
            }
        }
    }
    catch (std::filesystem::filesystem_error const& error)
    {
        return {false, error.what(), {}};
    }

    std::ranges::sort(paths);
    for (auto const& path : paths)
    {
        auto loaded = load_single_migration_file(path);
        if (!loaded.ok)
        {
            return loaded;
        }
        steps.insert(steps.end(), std::make_move_iterator(loaded.steps.begin()),
                     std::make_move_iterator(loaded.steps.end()));
    }
    return {true, {}, std::move(steps)};
}

auto build_offline_migration_plan(config::DatabaseConfig const& database_config, std::uint32_t current_version,
                                  std::uint32_t target_version, std::vector<MigrationStep> const& file_steps)
    -> OfflineMigrationPlanResult
{
    if (database_config.role != config::DatabaseRole::migration)
    {
        return {false, "database migration requires database.role=migration", {}};
    }
    auto plan = migration_plan_between(current_version, target_version);
    if (!file_steps.empty())
    {
        plan.steps = file_steps;
    }
    auto const validation = migration_plan_is_valid(plan);
    if (!validation.valid)
    {
        return {false, validation.reason, std::move(plan)};
    }
    return {true, {}, std::move(plan)};
}

auto offline_migrator_summary(OfflineMigrationPlanResult const& result) -> std::string
{
    if (!result.ok)
    {
        return "database migration rejected: " + result.reason;
    }
    return migration_plan_summary(result.plan);
}

} // namespace merovingian::database
