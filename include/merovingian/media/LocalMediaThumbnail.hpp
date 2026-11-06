// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::media
{

struct LocalMediaThumbnail final
{
    std::string media_id{};
    std::string storage_id{};
    std::uint32_t width{0U};
    std::uint32_t height{0U};
    std::string content_type{"image/png"};
    std::uint64_t size_bytes{0U};
};

} // namespace merovingian::media
