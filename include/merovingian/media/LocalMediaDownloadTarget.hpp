// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::media
{

// Where a servable local media file's bytes are (ADR-0119). The caller reads
// them with database::read_media_blob and then checks
// local_media_still_servable before serving them.
struct LocalMediaDownloadTarget final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string content_type{};
    std::string storage_id{};
    std::string reason{};
};

} // namespace merovingian::media
