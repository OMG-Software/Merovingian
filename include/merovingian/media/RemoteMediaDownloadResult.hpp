// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::media
{

struct RemoteMediaDownloadResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string reason{};
    std::string content_type{};
    std::string bytes{};
    std::uint64_t size_bytes{0U};
    std::string hash_algorithm{};
    std::string digest{};
    std::string storage_id{};
    std::string local_media_id{};
    bool quarantined{false};
    // True when this call admitted a new local record, which the caller must
    // make durable (ADR-0119); false when an existing cached record was reused.
    bool admitted_new_record{false};
    // True when that record's blob is new (or revived), so its bytes must be
    // written; false when it deduplicated onto stored bytes.
    bool stored_new_blob{false};
};

} // namespace merovingian::media
