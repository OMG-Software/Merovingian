// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later

#include "merovingian/database/library_versions.hpp"

#include "merovingian/core/library_version.hpp"

#include <bit>
#include <string>
#include <vector>

#include <libpq-fe.h>
#include <sqlite3.h>

#ifndef MEROVINGIAN_LIBPQ_BUILD_VERSION
#error "MEROVINGIAN_LIBPQ_BUILD_VERSION must be defined by the build (src/database/meson.build)"
#endif

namespace merovingian::database
{

auto format_libpq_version(int version) -> std::string
{
    if (version <= 0)
    {
        return {};
    }
    if (version >= 100000)
    {
        return std::to_string(version / 10000) + "." + std::to_string(version % 10000);
    }
    return std::to_string(version / 10000) + "." + std::to_string((version / 100) % 100) + "." +
           std::to_string(version % 100);
}

auto library_versions() -> std::vector<core::LibraryVersion>
{
    // sqlite3_libversion() returns SQLite's own sqlite3_version[]; libpq reports a number, so its
    // object is found from one of its functions.
    auto const* const sqlite_running = ::sqlite3_libversion();
    return {
        core::describe_library("SQLite", sqlite_running, SQLITE_VERSION, sqlite_running),
        core::describe_library("libpq", format_libpq_version(::PQlibVersion()), MEROVINGIAN_LIBPQ_BUILD_VERSION,
                               std::bit_cast<void const*>(&::PQlibVersion)),
    };
}

} // namespace merovingian::database
