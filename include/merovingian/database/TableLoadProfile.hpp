// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::database
{

// ADR-0062 part 2 (0.12.13 audit, finding N1): which tables a store open
// hydrates into memory. `full` is every process except the federation
// worker. `federation_worker` hydrates ONLY the tables
// federation_worker_table_allowlist names below — a fail-closed allowlist,
// not a denylist, so a worker connecting with a least-privilege PostgreSQL
// role (granted SELECT on exactly those tables) can still start, and a
// worker connecting with ANY role never holds unlisted material resident
// regardless of backend. Since ADR-0733 the worker opens no database: its
// store is in memory and filled from main, and `federation_worker` there only
// turns on asking main for keys on a miss
// (LocalDatabase::remote_signing_keys_read_through).
enum class TableLoadProfile
{
    full,
    federation_worker,
};

} // namespace merovingian::database
