// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/connection.hpp"
#include "merovingian/database/persistent_store.hpp"

#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace merovingian::database
{

struct PostgresqlConnectionPolicyResult final
{
    bool allowed{false};
    std::string reason{};
};

struct PostgresqlConnectionHandle;
struct PostgresqlConnectionOpenResult;

class PostgresqlConnection final : public DatabaseExecutor
{
public:
    PostgresqlConnection() noexcept;
    PostgresqlConnection(PostgresqlConnection const& other) = delete;
    auto operator=(PostgresqlConnection const& other) -> PostgresqlConnection& = delete;
    PostgresqlConnection(PostgresqlConnection&& other) noexcept;
    auto operator=(PostgresqlConnection&& other) noexcept -> PostgresqlConnection&;
    ~PostgresqlConnection() override;

    [[nodiscard]] auto open() const noexcept -> bool;
    [[nodiscard]] auto execute(PreparedStatement const& statement) -> QueryResult override;
    [[nodiscard]] auto execute_transaction(std::vector<PreparedStatement> const& statements) -> bool;

private:
    friend auto open_postgresql_connection(std::string_view conninfo) -> PostgresqlConnectionOpenResult;

    explicit PostgresqlConnection(std::unique_ptr<PostgresqlConnectionHandle> handle) noexcept;

    std::unique_ptr<PostgresqlConnectionHandle> handle_{};
};

struct PostgresqlConnectionOpenResult final
{
    bool ok{false};
    std::string reason{};
    std::string redacted_conninfo{};
    PostgresqlConnection connection{};
};

[[nodiscard]] auto validate_postgresql_conninfo(std::string_view conninfo) -> PostgresqlConnectionPolicyResult;
[[nodiscard]] auto redact_postgresql_conninfo(std::string_view conninfo) -> std::string;
[[nodiscard]] auto postgresql_schema_bootstrap_statements() -> std::vector<PreparedStatement>;
[[nodiscard]] auto open_postgresql_connection(std::string_view conninfo) -> PostgresqlConnectionOpenResult;
[[nodiscard]] auto open_postgresql_persistent_store(std::string_view conninfo) -> PersistentStoreOpenResult;

// Switch the session role on `connection` to `role_name`. Returns false if
// the connection is not open or `SET ROLE` fails (e.g. the current login
// role is not a member of the target role). Role names are quoted with
// PostgreSQL identifier rules so a malicious caller cannot inject SQL.
[[nodiscard]] auto set_postgresql_role(PostgresqlConnection& connection, std::string_view role_name) -> bool;

// Resets the session role to the connecting login role via `RESET ROLE`.
// Useful in tests that switch to a restricted runtime role and need to
// return to the bootstrapping migration role.
[[nodiscard]] auto reset_postgresql_role(PostgresqlConnection& connection) -> bool;

// Returns the value of CURRENT_USER on `connection`. Empty when the
// connection is not open or the query fails. Used by tests that need to
// assert role switching took effect.
[[nodiscard]] auto current_postgresql_user(PostgresqlConnection& connection) -> std::string;

} // namespace merovingian::database
