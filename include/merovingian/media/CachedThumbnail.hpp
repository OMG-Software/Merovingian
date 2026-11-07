// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::media
{

struct CachedThumbnail final
{
    std::string content_type{};
    std::string bytes{};
};

} // namespace merovingian::media
