// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/statement.hpp"

#include <algorithm>
#include <cstddef>
#include <vector>

namespace merovingian::database
{
namespace
{

    [[nodiscard]] auto is_statement_name_character(char value) noexcept -> bool
    {
        return (value >= 'a' && value <= 'z') || (value >= '0' && value <= '9') || value == '_';
    }

    [[nodiscard]] auto is_digit(char value) noexcept -> bool
    {
        return value >= '0' && value <= '9';
    }

    [[nodiscard]] auto contains_forbidden_sql_fragment(std::string_view sql) noexcept -> bool
    {
        return sql.find(';') != std::string_view::npos || sql.find("--") != std::string_view::npos ||
               sql.find("/*") != std::string_view::npos || sql.find("*/") != std::string_view::npos;
    }

    [[nodiscard]] auto starts_with_allowed_verb(std::string_view sql) noexcept -> bool
    {
        // SET/RESET cover session-level role switching. BEGIN/COMMIT/ROLLBACK/
        // SAVEPOINT cover explicit transaction-control statements used by the
        // live PostgreSQL durability scenarios. These statements never carry
        // row-shaped user input, so allowing their fixed leading verbs keeps
        // the boundary narrow while letting transaction semantics be exercised
        // through the same validated executor path.
        return sql.starts_with("SELECT ") || sql.starts_with("INSERT ") || sql.starts_with("UPDATE ") ||
               sql.starts_with("DELETE ") || sql.starts_with("CREATE ") || sql.starts_with("ALTER ") ||
               sql.starts_with("DROP ") || sql.starts_with("SET ") || sql.starts_with("RESET ") ||
               sql.starts_with("BEGIN") || sql.starts_with("COMMIT") || sql.starts_with("ROLLBACK") ||
               sql.starts_with("SAVEPOINT ");
    }

    [[nodiscard]] auto placeholder_arity_matches(std::string_view sql, std::size_t parameter_count) -> bool
    {
        auto placeholders = std::vector<bool>(parameter_count + 1U, false);
        auto highest_placeholder = std::size_t{0U};

        for (auto index = std::size_t{0U}; index < sql.size(); ++index)
        {
            if (sql[index] != '$')
            {
                continue;
            }

            auto cursor = index + 1U;
            if (cursor >= sql.size() || !is_digit(sql[cursor]))
            {
                return false;
            }

            auto placeholder = std::size_t{0U};
            while (cursor < sql.size() && is_digit(sql[cursor]))
            {
                placeholder = (placeholder * 10U) + static_cast<std::size_t>(sql[cursor] - '0');
                ++cursor;
            }

            if (placeholder == 0U || placeholder > parameter_count)
            {
                return false;
            }

            highest_placeholder = std::max(highest_placeholder, placeholder);
            placeholders[placeholder] = true;
            index = cursor - 1U;
        }

        if (highest_placeholder != parameter_count)
        {
            return false;
        }

        for (auto placeholder = std::size_t{1U}; placeholder <= highest_placeholder; ++placeholder)
        {
            if (!placeholders[placeholder])
            {
                return false;
            }
        }

        return true;
    }

} // namespace

auto statement_name_is_valid(std::string_view name) noexcept -> bool
{
    return !name.empty() && name.size() <= 96U && std::ranges::all_of(name, is_statement_name_character);
}

auto sql_shape_is_allowed(std::string_view sql) noexcept -> bool
{
    return !sql.empty() && sql.size() <= 16'384U && starts_with_allowed_verb(sql) &&
           !contains_forbidden_sql_fragment(sql);
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
    if (!placeholder_arity_matches(statement.sql, statement.parameters.size()))
    {
        return {false, "SQL placeholder arity does not match bound parameters"};
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
