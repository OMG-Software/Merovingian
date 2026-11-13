// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/Config.hpp"

namespace merovingian::federation_worker
{

// The federation worker opens no database (ADR-0733): main sends it the rows it reads over the IPC channel.

// Switches `config` to `database.backend=memory` and empties every database location in it: the SQLite path, the
// PostgreSQL URI file, both roles and the per-process connection override. main.cpp calls it on the worker's copy
// before it builds the Landlock rules, so no database directory is granted, and WorkerEventLoop::run() calls it again
// on its own copy before it starts the runtime, as it clears the master-key path, so the runtime opens an in-memory
// store and nothing else whoever constructed the loop.
auto clear_database_location(config::Config& config) noexcept -> void;

} // namespace merovingian::federation_worker
