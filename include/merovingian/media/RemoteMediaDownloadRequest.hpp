// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::media
{

struct RemoteMediaDownloadRequest final
{
    std::string origin_server{};
    std::string media_id{};
    std::string resolved_host{};
    std::vector<std::string> resolved_addresses{};
    std::string content_type{};
    std::string bytes{};
    bool scanner_clean{true};
    std::uint64_t decoded_size_bytes{0U};
    std::uint64_t pixel_count{0U};
    std::uint64_t animation_frame_count{1U};
    bool decoder_marked_safe{true};
    // R17: the filename in the remote server's Content-Disposition, if any.
    std::string upload_name{};
};

} // namespace merovingian::media
