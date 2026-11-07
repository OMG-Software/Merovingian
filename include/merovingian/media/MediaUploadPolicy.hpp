// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/media/MediaAcceptancePolicy.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace merovingian::media
{

struct MediaUploadPolicy final
{
    std::uint64_t max_upload_bytes{0U};
    std::vector<std::string> allowed_mime_types{};
    bool require_content_sniffing{true};
    bool quarantine_unknown_mime{true};
    bool quarantine_scanner_failures{true};
    MediaAcceptancePolicy acceptance_policy{MediaAcceptancePolicy::allow_after_scan};
};

} // namespace merovingian::media
