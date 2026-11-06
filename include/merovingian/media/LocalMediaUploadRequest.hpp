// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::media
{

struct LocalMediaUploadRequest final
{
    std::string owner_user_id{};
    std::string declared_mime_type{};
    std::string sniffed_mime_type{};
    std::string bytes{};
    bool scanner_clean{true};
    std::uint64_t decoded_size_bytes{0U};
    std::uint64_t pixel_count{0U};
    std::uint64_t animation_frame_count{1U};
    bool decoder_marked_safe{true};
    // True when these bytes came from fetch_remote_media() rather than a
    // client's own upload. Selects RuntimeMediaConfig::remote_fetch_media_policy
    // instead of local_upload_policy when evaluating acceptance.
    bool from_remote_fetch{false};
    // The upload's `filename` (R17), already validated by
    // media_filename_is_valid; stored on the record.
    std::string upload_name{};
    // ADR-0212: the reserved media ID this upload fills (PUT
    // /_matrix/media/v3/upload/{serverName}/{mediaId}); empty mints a fresh
    // one. The caller has checked the reservation with admit_pending_media_upload.
    std::string media_id{};
};

} // namespace merovingian::media
