// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace merovingian::database
{

// A secondary index: `CREATE INDEX name ON table (columns_sql)`.
struct SchemaIndexDefinition final
{
    std::string_view name{};
    std::string_view table{};
    std::string_view columns_sql{};
};

} // namespace merovingian::database
