// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

namespace merovingian::config
{

enum class DatabaseBackend
{
    postgresql,
    sqlite,
    // Explicit programmatic backend for tests only. The config parser does not
    // accept "memory"; deployed configuration must choose a durable backend.
    memory,
};

} // namespace merovingian::config
