// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/PersistentStoreBackend.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace merovingian::database
{

// ADR-0574: a download larger than this is sent in chunks of this size, read from the database one at a time,
// so the memory a transfer holds is this, not the file. A file this size or smaller is read whole.
inline constexpr std::size_t media_blob_chunk_bytes = 256U * 1024U;

// ADR-0119: media bytes live only in the database and are read per request.
// prepare_media_blob_read runs under the runtime mutex and captures where to
// read from; read_media_blob then runs with the mutex released. The SQLite
// path and PostgreSQL connection details are fixed once the store is open.
// The memory backend has no other copy of the bytes, so they are copied here.
struct MediaBlobRead final
{
    PersistentStoreBackend backend{PersistentStoreBackend::memory};
    std::string storage_id{};
    std::string sqlite_path{};
    std::string_view postgresql_conninfo{};
    std::string_view postgresql_runtime_role{};
    std::optional<std::string> memory_bytes{};
};

} // namespace merovingian::database
