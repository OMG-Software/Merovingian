// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/media/ThumbnailMethod.hpp"
#include "merovingian/media/ThumbnailSourceFormat.hpp"

#include <cstdint>
#include <string>

namespace merovingian::media
{

// A decode+resample job handed to the worker over its stdin pipe.
struct ThumbnailWorkerRequest final
{
    ThumbnailSourceFormat format{ThumbnailSourceFormat::png};
    ThumbnailMethod method{ThumbnailMethod::scale};
    std::uint32_t target_width{0U};
    std::uint32_t target_height{0U};
    std::uint32_t max_pixels{0U}; // decode guard: reject images above this area
    std::string source_bytes{};
};

} // namespace merovingian::media
