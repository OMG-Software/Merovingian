// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/database/MediaBlobRead.hpp"

#include <cstdint>

namespace merovingian::homeserver
{

// ADR-0574: a response body the HTTP layer reads from the database in chunks while it writes, instead of a body
// held in memory. `blob` says where the bytes are (captured under the runtime mutex, fixed once the store is
// open) and `size_bytes` is the stored length, which is the response's Content-Length. It holds no connection:
// every chunk is read on a connection that is closed before the chunk is written to the client.
struct MediaBodyStream final
{
    database::MediaBlobRead blob{};
    std::uint64_t size_bytes{0U};
};

} // namespace merovingian::homeserver
