// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/media/PendingMediaUpload.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::media
{

// ADR-0212: reserving an mxc:// URI for a later upload. Expired reservations
// found on the way are listed in `expired_media_ids` so the caller deletes
// them in the same transaction.
struct PendingMediaUploadPlan final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string reason{};
    PendingMediaUpload reservation{};
    std::vector<std::string> expired_media_ids{};
};

} // namespace merovingian::media
