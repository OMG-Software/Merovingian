// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <merovingian/config/config.hpp>

#include <cstdint>
#include <string>

namespace merovingian::database
{

struct RuntimeDatabaseConfig final
{
    std::string uri_file{};
    std::uint32_t pool_size{0U};
};

[[nodiscard]] auto make_runtime_database_config(config::Config const& config) -> RuntimeDatabaseConfig;
[[nodiscard]] auto database_summary(RuntimeDatabaseConfig const& config) -> std::string;

} // namespace merovingian::database
