// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::media
{

// Resampling method requested by the client (Matrix CS API §thumbnails).
// `scale` fits the image within the box preserving aspect ratio; `crop`
// fills the box and trims the overflow, also preserving aspect ratio.
enum class ThumbnailMethod : std::uint8_t
{
    scale = 0U,
    crop = 1U,
};

} // namespace merovingian::media
