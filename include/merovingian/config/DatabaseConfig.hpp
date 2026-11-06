// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/DatabaseBackend.hpp"
#include "merovingian/config/DatabaseRole.hpp"

#include <cstdint>
#include <string>

namespace merovingian::config
{

struct DatabaseConfig final
{
    std::string uri_file{"/etc/merovingian/db-uri"};
    std::uint32_t pool_size{16U};
    DatabaseBackend backend{DatabaseBackend::postgresql};
    DatabaseRole role{DatabaseRole::runtime};
    // PostgreSQL role separation (packaging/postgresql/provision-roles.sql).
    // The login role is granted two NOLOGIN roles: one with DDL rights used
    // for the migration phase, one with DML-only rights used to serve. Both
    // empty means no SET ROLE is issued and the connection keeps whatever
    // privileges its login role has — the pre-separation behaviour, so an
    // existing single-role deployment is unaffected by upgrading.
    //
    // When either IS set, a failed SET ROLE aborts the open. Continuing would
    // serve traffic with more privilege than the operator asked for, which is
    // the exact outcome this separation exists to prevent.
    std::string migration_role{};
    std::string runtime_role{};
    std::string sqlite_path{"/var/lib/merovingian/merovingian.sqlite3"};
    // Process-local override for the federation worker's own database
    // connection string (ADR-0062 part 2). Never parsed from a config file
    // and never logged: `federation_worker::apply_worker_database_uri`
    // populates this on the worker's own in-memory Config copy, from bytes
    // main handed it over the inherited kWorkerDbUriFd pipe, immediately
    // before `bootstrap_local_database` opens the store. When non-empty it
    // takes priority over `uri_file` for that one open. Main's own Config
    // (and every other process) always leaves this empty.
    std::string worker_conninfo_override{};
};

} // namespace merovingian::config
