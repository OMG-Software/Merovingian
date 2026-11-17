// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/SchemaIndexDefinition.hpp"
#include "merovingian/database/SchemaTableDefinition.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::database
{

[[nodiscard]] auto current_schema_version() noexcept -> std::uint32_t;
// The schema split (ADR-0778). The tables and indexes migration `version` creates: version 1 is the frozen v1
// schema, version 2 the OAuth 2.0 tables, version 3 the delayed-events table; any other version adds none. A migration step is built from these.
[[nodiscard]] auto schema_definitions_added_by(std::uint32_t version) -> std::vector<SchemaTableDefinition>;
[[nodiscard]] auto schema_indexes_added_by(std::uint32_t version) -> std::vector<SchemaIndexDefinition>;
// Exactly what v1 created, which the SQLite and PostgreSQL bootstraps build before any later step runs.
[[nodiscard]] auto initial_schema_definitions() -> std::vector<SchemaTableDefinition>;
// Every version up to current_schema_version(), in order: what a migrated database holds.
[[nodiscard]] auto current_schema_definitions() -> std::vector<SchemaTableDefinition>;
[[nodiscard]] auto initial_schema_indexes() -> std::vector<SchemaIndexDefinition>;
[[nodiscard]] auto current_schema_indexes() -> std::vector<SchemaIndexDefinition>;
[[nodiscard]] auto initial_schema_tables() -> std::vector<std::string_view>;
[[nodiscard]] auto current_schema_tables() -> std::vector<std::string_view>;
// A table of the current schema (any version), by name; nullopt for any other name.
[[nodiscard]] auto schema_table_definition(std::string_view table_name) noexcept
    -> std::optional<SchemaTableDefinition>;
// True for a table of the current schema, of whichever version. Only these may appear in generated DDL.
[[nodiscard]] auto schema_table_is_core(std::string_view table_name) noexcept -> bool;
[[nodiscard]] auto quote_sqlite_identifier(std::string_view identifier) noexcept -> std::optional<std::string>;
[[nodiscard]] auto create_table_sql(SchemaTableDefinition const& table) -> std::optional<std::string>;
// Refuse (nullopt) any index that is not one of current_schema_indexes().
[[nodiscard]] auto create_index_sql(SchemaIndexDefinition const& index) -> std::optional<std::string>;
[[nodiscard]] auto create_index_if_missing_sql(SchemaIndexDefinition const& index) -> std::optional<std::string>;

} // namespace merovingian::database
