// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

// A PostgreSQL database of a scenario's own, on the server the live tests use.
//
// The live PostgreSQL scenarios share one database (MEROVINGIAN_TEST_POSTGRESQL_URI).
// A runtime started on it replays every row an earlier scenario left in
// federation_transactions, deferred_pdus and the other durable queues, and its
// background workers then write to the store at moments the scenario does not
// control. A scenario that needs an empty schema, or a quiet store, opens its
// runtime on one of these instead. The database is dropped when the object goes,
// however the scenario ends, so declare it before anything that connects to it.

#include <chrono>
#include <memory>
#include <string>
#include <tuple>
#include <utility>

#include <libpq-fe.h>

namespace merovingian::tests
{

// The same server as `conninfo`, another database. Handles both libpq forms.
[[nodiscard]] inline auto conninfo_for_database(std::string const& conninfo, std::string const& database) -> std::string
{
    auto const scheme = conninfo.find("://");
    if (scheme == std::string::npos)
    {
        // Keyword/value form: a later keyword overrides an earlier one.
        return conninfo + " dbname=" + database;
    }
    auto const path = conninfo.find('/', scheme + 3U);
    auto const query = conninfo.find('?', scheme + 3U);
    auto const authority_end = path < query ? path : query;
    auto const rest = query == std::string::npos ? std::string{} : conninfo.substr(query);
    return conninfo.substr(0U, authority_end) + "/" + database + rest;
}

class ScratchPostgresqlDatabase final
{
public:
    // `admin_conninfo` must be allowed to CREATE and DROP DATABASE.
    explicit ScratchPostgresqlDatabase(std::string admin_conninfo)
        : admin_conninfo_{std::move(admin_conninfo)}
        , name_{"merovingian_scratch_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count())}
        , created_{execute(admin_conninfo_, "CREATE DATABASE " + name_)}
    {
    }
    ScratchPostgresqlDatabase(ScratchPostgresqlDatabase const& other) = delete;
    auto operator=(ScratchPostgresqlDatabase const& other) -> ScratchPostgresqlDatabase& = delete;
    ScratchPostgresqlDatabase(ScratchPostgresqlDatabase&& other) = delete;
    auto operator=(ScratchPostgresqlDatabase&& other) -> ScratchPostgresqlDatabase& = delete;
    ~ScratchPostgresqlDatabase()
    {
        if (created_)
        {
            // FORCE ends any session a runtime still holds open on it.
            std::ignore = execute(admin_conninfo_, "DROP DATABASE IF EXISTS " + name_ + " WITH (FORCE)");
        }
    }

    [[nodiscard]] auto created() const noexcept -> bool
    {
        return created_;
    }

    [[nodiscard]] auto conninfo() const -> std::string
    {
        return conninfo_for_database(admin_conninfo_, name_);
    }

private:
    struct Finish final
    {
        auto operator()(PGconn* connection) const noexcept -> void
        {
            PQfinish(connection);
        }
    };

    struct Clear final
    {
        auto operator()(PGresult* result) const noexcept -> void
        {
            PQclear(result);
        }
    };

    // The name is generated above, never taken from input, so the statement is
    // built rather than bound: CREATE/DROP DATABASE take no parameters.
    [[nodiscard]] static auto execute(std::string const& conninfo, std::string const& sql) -> bool
    {
        auto const connection = std::unique_ptr<PGconn, Finish>{PQconnectdb(conninfo.c_str())};
        if (PQstatus(connection.get()) != CONNECTION_OK)
        {
            return false;
        }
        auto const result = std::unique_ptr<PGresult, Clear>{PQexec(connection.get(), sql.c_str())};
        return PQresultStatus(result.get()) == PGRES_COMMAND_OK;
    }

    std::string admin_conninfo_{};
    std::string name_{};
    bool created_{false};
};

} // namespace merovingian::tests
