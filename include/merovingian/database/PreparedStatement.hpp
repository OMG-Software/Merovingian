// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/BoundValue.hpp"
#include "merovingian/database/StatementValidationResult.hpp"

#include <string>
#include <string_view>
#include <vector>

namespace merovingian::database
{

struct PreparedStatement final
{
    std::string name{};
    std::string sql{};
    std::vector<BoundValue> parameters{};
};

[[nodiscard]] auto statement_name_is_valid(std::string_view name) noexcept -> bool;
[[nodiscard]] auto sql_shape_is_allowed(std::string_view sql) noexcept -> bool;
[[nodiscard]] auto prepared_statement_is_valid(PreparedStatement const& statement) -> StatementValidationResult;
[[nodiscard]] auto redacted_parameter_summary(std::vector<BoundValue> const& parameters) -> std::string;

} // namespace merovingian::database
