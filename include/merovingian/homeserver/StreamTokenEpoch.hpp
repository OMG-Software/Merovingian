// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#pragma once

namespace merovingian::config
{
class Config;
} // namespace merovingian::config

namespace merovingian::database
{
struct PersistentStore;
} // namespace merovingian::database

namespace merovingian::homeserver
{

// ADR-0592: gives a database that has no stream token epoch yet (a fresh one) a random one and persists it. A
// database that has one keeps it. False, and logged, when no random value could be drawn or the write failed;
// the main process then refuses to start, since tokens it issued could not be told from another database's.
[[nodiscard]] auto ensure_stream_token_epoch(database::PersistentStore& store) -> bool;

// ADR-0592: `merovingian-server --after-restore`. Opens the configured database and replaces its stream token
// epoch with a fresh random one, so every sync token issued before the restore (whatever its positions) is
// served as an initial sync, and a to-device `since` from before it acknowledges nothing. Random, not
// incremented: the same backup can be restored twice, and an incremented epoch would then repeat. Run once,
// with the server stopped, after restoring a backup and before starting the server. False, and logged, when
// the database cannot be opened, is the in-memory backend, or the write fails.
[[nodiscard]] auto begin_stream_token_epoch_after_restore(config::Config const& config) -> bool;

} // namespace merovingian::homeserver
