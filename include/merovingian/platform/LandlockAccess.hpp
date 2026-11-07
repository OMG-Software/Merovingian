// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::platform
{

// The access class granted to one path in the worker's Landlock ruleset.
enum class LandlockAccess : std::uint8_t
{
    // READ_FILE (+ READ_DIR so directory listings and traversal succeed).
    read_only,
    // read_only rights plus EXECUTE, for shared-library directories the
    // dynamic linker / NSS / dlopen() need to map executable pages from.
    read_execute,
    // Full read/write/create/remove rights (never EXECUTE, never
    // MAKE_CHAR/MAKE_SOCK/MAKE_FIFO/MAKE_BLOCK). Used only for the SQLite
    // database directory.
    read_write,
};

} // namespace merovingian::platform
