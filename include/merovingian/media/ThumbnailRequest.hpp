// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/media/ThumbnailMethod.hpp"

#include <cstdint>
#include <string>

namespace merovingian::media
{

// Parent-facing request: the original media bytes plus the requested geometry.
struct ThumbnailRequest final
{
    std::string source_bytes{};
    std::string source_content_type{};
    std::uint32_t width{0U};
    std::uint32_t height{0U};
    ThumbnailMethod method{ThumbnailMethod::scale};
};

} // namespace merovingian::media
