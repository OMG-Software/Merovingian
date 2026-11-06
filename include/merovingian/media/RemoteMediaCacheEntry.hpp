// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::media
{

struct RemoteMediaCacheEntry final
{
    std::string origin_server{};
    std::string media_id{};
    std::string local_media_id{};
    std::uint64_t expires_at_ms{0U};
    std::uint64_t last_access_ms{0U};
    // F-47, ADR-0341: the size of the file the entry points at, set when the
    // entry is admitted or restored, so planning an admission sizes the cache
    // without looking each record up.
    std::uint64_t size_bytes{0U};
};

} // namespace merovingian::media
