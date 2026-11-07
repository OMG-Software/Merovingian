// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/media/ThumbnailMethod.hpp"

#include <cstdint>
#include <string>

namespace merovingian::media
{

// Which thumbnail of which stored bytes. `media_id` and `storage_id` are the
// local record that authorised the decode (for remote media, the cached local
// record), so a replaced blob or a re-admitted remote file never hits an old
// entry.
struct ThumbnailCacheKey final
{
    std::string media_id{};
    std::string storage_id{};
    std::uint32_t width{0U};
    std::uint32_t height{0U};
    ThumbnailMethod method{ThumbnailMethod::scale};
};

} // namespace merovingian::media
