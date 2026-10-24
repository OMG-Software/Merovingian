// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/core/library_version.hpp"

#include <vector>

namespace merovingian::homeserver
{

// Every library the server and the federation worker link, each reported by the module that owns
// it: libsodium (crypto), OpenSSL (the TLS listener, here), libpq and SQLite (database), libcurl
// (http) and yyjson (canonicaljson). Logged at startup by both executables (0.12.45); the
// thumbnail worker's libraries come from media::query_thumbnail_worker_libraries.
[[nodiscard]] auto linked_library_versions() -> std::vector<core::LibraryVersion>;

} // namespace merovingian::homeserver
