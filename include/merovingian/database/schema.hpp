// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string_view>
#include <vector>

namespace merovingian::database
{

[[nodiscard]] auto current_schema_version() noexcept -> std::uint32_t;
[[nodiscard]] auto initial_schema_tables() -> std::vector<std::string_view>;
[[nodiscard]] auto schema_table_is_core(std::string_view table_name) noexcept -> bool;

} // namespace merovingian::database
