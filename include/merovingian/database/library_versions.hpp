// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/library_version.hpp"

#include <string>
#include <vector>

namespace merovingian::database
{

// SQLite and libpq, as linked into this executable.
[[nodiscard]] auto library_versions() -> std::vector<core::LibraryVersion>;

// PQlibVersion() as its release is named: major.minor from PostgreSQL 10 (180001 is "18.1"),
// major.minor.patch before it (90624 is "9.6.24"); empty for a value that is not a version.
[[nodiscard]] auto format_libpq_version(int version) -> std::string;

} // namespace merovingian::database
