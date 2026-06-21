// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/config/config.hpp"
#include "merovingian/database/migration_files.hpp"

#include <cstdint>
#include <iostream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace
{

constexpr auto version = std::string_view{"0.9.13"};

auto print_help() -> void
{
    std::cout << "merovingian-db-migrate " << version << '\n'
              << "Usage:\n"
              << "  merovingian-db-migrate --plan <current-version> <target-version> [--migrations <directory>]\n";
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

    auto database = merovingian::config::DatabaseConfig{};
    database.role = merovingian::config::DatabaseRole::migration;
    auto plan = merovingian::database::build_offline_migration_plan(database, parse_u32(argv[2]), parse_u32(argv[3]),
                                                                    file_steps);
    std::cout << merovingian::database::offline_migrator_summary(plan) << '\n';
    return plan.ok ? 0 : 78;
}
