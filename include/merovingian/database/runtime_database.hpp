// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/config.hpp"

#include <cstdint>
#include <string>

namespace merovingian::database
{

struct RuntimeDatabaseConfig final
{
    config::DatabaseBackend backend{config::DatabaseBackend::postgresql};
    std::string uri_file{};
    std::string sqlite_path{};
    std::uint32_t pool_size{0U};
    config::DatabaseRole role{config::DatabaseRole::runtime};
    std::string warning{};
};

[[nodiscard]] auto make_runtime_database_config(config::Config const& config) -> RuntimeDatabaseConfig;
[[nodiscard]] auto database_summary(RuntimeDatabaseConfig const& config) -> std::string;

} // namespace merovingian::database
