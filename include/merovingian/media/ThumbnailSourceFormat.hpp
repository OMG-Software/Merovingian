// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::media
{

// Source pixel format the worker should decode. Only the still-image formats
// the resampler supports are represented; animated/unsupported types never
// reach the worker.
enum class ThumbnailSourceFormat : std::uint8_t
{
    png = 0U,
    jpeg = 1U,
};

} // namespace merovingian::media
