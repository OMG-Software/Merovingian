// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::database
{

struct SchemaTableDefinition final
{
    std::string_view name{};
    std::string_view columns_sql{};
};

[[nodiscard]] auto current_schema_version() noexcept -> std::uint32_t;
[[nodiscard]] auto initial_schema_definitions() -> std::vector<SchemaTableDefinition>;
[[nodiscard]] auto initial_schema_tables() -> std::vector<std::string_view>;
[[nodiscard]] auto schema_table_definition(std::string_view table_name) noexcept
    -> std::optional<SchemaTableDefinition>;
[[nodiscard]] auto schema_table_is_core(std::string_view table_name) noexcept -> bool;
[[nodiscard]] auto create_table_sql(SchemaTableDefinition const& table) -> std::string;

} // namespace merovingian::database
