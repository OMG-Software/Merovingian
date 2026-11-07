// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::media
{

// Parent-facing result. `ok` thumbnails always carry `image/png` bytes.
struct ThumbnailResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string content_type{};
    std::string bytes{};
    std::uint32_t width{0U};
    std::uint32_t height{0U};
    std::string reason{};
};

} // namespace merovingian::media
