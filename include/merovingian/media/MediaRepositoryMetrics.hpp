// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::media
{

struct MediaRepositoryMetrics final
{
    std::uint64_t uploads_accepted{0U};
    std::uint64_t uploads_rejected{0U};
    std::uint64_t uploads_quarantined{0U};
    std::uint64_t downloads_served{0U};
    std::uint64_t downloads_blocked{0U};
    std::uint64_t deduplicated_uploads{0U};
    std::uint64_t admin_quarantines{0U};
    std::uint64_t admin_releases{0U};
    std::uint64_t admin_removals{0U};
    std::uint64_t remote_fetch_rejections{0U};
    std::uint64_t remote_fetches_accepted{0U};
    std::uint64_t processing_rejections{0U};
    std::uint64_t thumbnails_generated{0U};
    std::uint64_t thumbnails_served{0U};
    std::uint64_t stored_blobs{0U};
    std::uint64_t stored_bytes{0U};
};

} // namespace merovingian::media
