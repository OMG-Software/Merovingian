// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/config.hpp"
#include "merovingian/database/migration_files.hpp"

#include <cstdint>
#include <iostream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

constexpr auto version = std::string_view{"0.12.11"};

auto print_help() -> void
{
    std::cout << "merovingian-db-migrate " << version << '\n'
              << "Usage:\n"
              << "  merovingian-db-migrate --plan <current-version> <target-version> [--migrations <directory>]\n";
}

// L-08 (security audit 2026-09): returns nullopt for anything that is not a
// plain decimal integer in range, rather than folding empty input, "abc" and
// "99999999999999" all into 0. `merovingian-db-migrate --plan abc def` used to
// build a current=0 target=0 plan with no steps and exit 0, telling an operator
// that a migration they mistyped had nothing to do.
[[nodiscard]] auto parse_u32(std::string_view value) noexcept -> std::optional<std::uint32_t>
{
    if (value.empty())
    {
        return std::nullopt;
    }
    auto result = std::uint64_t{0U};
    for (auto const character : value)
    {
        if (character < '0' || character > '9')
        {
            return std::nullopt;
        }
        result = (result * 10U) + static_cast<std::uint64_t>(character - '0');
        if (result > std::numeric_limits<std::uint32_t>::max())
        {
            return std::nullopt;
        }
    }
    return static_cast<std::uint32_t>(result);
}

} // namespace

auto main(int argc, char const* const* argv) -> int
{
    if (argc == 2 && (std::string_view{argv[1]} == "--help" || std::string_view{argv[1]} == "--version"))
    {
        print_help();
        return 0;
    }
    if (argc != 4 && argc != 6)
    {
        print_help();
        return 64;
    }
    if (std::string_view{argv[1]} != "--plan")
    {
        print_help();
        return 64;
    }

    auto file_steps = std::vector<merovingian::database::MigrationStep>{};
    if (argc == 6)
    {
        if (std::string_view{argv[4]} != "--migrations")
        {
            print_help();
            return 64;
        }
        auto loaded = merovingian::database::load_migration_files(argv[5]);
        if (!loaded.ok)
        {
            std::cerr << loaded.reason << '\n';
            return 65;
        }
        file_steps = std::move(loaded.steps);
    }

    auto const current_version = parse_u32(argv[2]);
    auto const target_version = parse_u32(argv[3]);
    if (!current_version.has_value() || !target_version.has_value())
    {
        std::cerr << "error: <current-version> and <target-version> must be decimal integers in [0, "
                  << std::numeric_limits<std::uint32_t>::max() << "]\n";
        print_help();
        return 64;
    }

    auto database = merovingian::config::DatabaseConfig{};
    database.role = merovingian::config::DatabaseRole::migration;
    auto plan =
        merovingian::database::build_offline_migration_plan(database, *current_version, *target_version, file_steps);
    std::cout << merovingian::database::offline_migrator_summary(plan) << '\n';
    return plan.ok ? 0 : 78;
}
