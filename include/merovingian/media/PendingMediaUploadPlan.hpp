// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/media/PendingMediaUpload.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::media
{

// F-16: the most expired reservations one create sweeps. A backlog is cleared by later creates, 256 at a time; until
// then an expired reservation that has not been swept is dead to every reader (it counts toward no quota, admits no
// upload and satisfies no wait). It must equal database::max_pending_media_deleted_per_commit.
inline constexpr std::size_t max_expired_reservations_swept_per_create{256U};

// ADR-0212: reserving an mxc:// URI for a later upload. Expired reservations
// found on the way are listed in `expired_media_ids` (at most
// max_expired_reservations_swept_per_create of them) so the caller deletes
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
