// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/media/thumbnailer.hpp"

#include <cstdint>
#include <string>

namespace merovingian::federation
{

// What an inbound `GET /_matrix/federation/v1/media/thumbnail/{mediaId}` asks for. The handler has
// validated the dimensions (positive integers) and the method; `origin` is the X-Matrix-authenticated
// requesting server, which the provider counts the decode against.
struct FederationThumbnailQuery final
{
    std::string media_id{};
    std::uint32_t width{0U};
    std::uint32_t height{0U};
    media::ThumbnailMethod method{media::ThumbnailMethod::scale};
    std::string origin{};
};

} // namespace merovingian::federation
