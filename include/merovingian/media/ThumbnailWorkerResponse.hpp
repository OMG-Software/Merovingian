// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/media/ThumbnailWorkerStatus.hpp"

#include <cstdint>
#include <string>

namespace merovingian::media
{

// The worker's reply, read from its stdout pipe.
struct ThumbnailWorkerResponse final
{
    ThumbnailWorkerStatus status{ThumbnailWorkerStatus::internal_error};
    std::uint32_t width{0U};
    std::uint32_t height{0U};
    std::string png_bytes{};
};

} // namespace merovingian::media
