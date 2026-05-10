// SPDX-License-Identifier: GPL-3.0-or-later

#include <merovingian/database/statement.hpp>

#include <algorithm>
#include <cstddef>

namespace merovingian::database
{
namespace
{

[[nodiscard]] auto is_statement_name_character(char value) noexcept -> bool
{
    return (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') || value == '_';
}

[[nodiscard]] auto contains_forbidden_sql_fragment(std::string_view sql) noexcept -> bool
{
    return sql.find(';') != std::string_view::npos || sql.find("--") != std::string_view::npos
        || sql.find("/*") != std::string_view::npos || sql.find("*/") != std::string_view::npos;
}

[[nodiscard]] auto starts_with_allowed_verb(std::string_view sql) noexcept -> bool
{
    return sql.starts_with("SELECT ") || sql.starts_with("INSERT ") || sql.starts_with("UPDATE ")
        || sql.starts_with("DELETE ") || sql.starts_with("CREATE ") || sql.starts_with("ALTER ")
        || sql.starts_with("DROP ");
}

} // namespace

auto statement_name_is_valid(std::string_view name) noexcept -> bool
{
    return !name.empty() && name.size() <= 96U && std::ranges::all_of(name, is_statement_name_character);
}

auto sql_shape_is_allowed(std::string_view sql) noexcept -> bool
{
    return !sql.empty() && sql.size() <= 16'384U && starts_with_allowed_verb(sql) && !contains_forbidden_sql_fragment(sql);
}

auto prepared_statement_is_valid(PreparedStatement const& statement) -> StatementValidationResult
{
    if (!statement_name_is_valid(statement.name))
    {
        return {false, "invalid statement name"};
    }
    if (!sql_shape_is_allowed(statement.sql))
    {
        return {false, "SQL shape is not allowed"};
    }
    if (statement.parameters.size() > 128U)
    {
        return {false, "too many statement parameters"};
    }

    return {true, {}};
}

auto redacted_parameter_summary(std::vector<BoundValue> const& parameters) -> std::string
{
    auto summary = std::string{"parameters="} + std::to_string(parameters.size()) + " [";
    for (std::size_t index = 0; index < parameters.size(); ++index)
    {
        if (index != 0U)
        {
            summary += ", ";
        }
        summary += parameters[index].sensitive ? "redacted" : "present";
    }
    summary += ']';
    return summary;
}

} // namespace merovingian::database
