// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::media
{

// Status the sandboxed worker reports back for a single request. Anything other
// than `ok` means no thumbnail bytes were produced.
enum class ThumbnailWorkerStatus : std::uint8_t
{
    ok = 0U,
    decode_failed = 1U,
    too_large = 2U,
    unsupported = 3U,
    internal_error = 4U,
};

} // namespace merovingian::media
