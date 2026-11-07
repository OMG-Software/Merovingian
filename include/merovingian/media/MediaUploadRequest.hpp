// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::media
{

struct MediaUploadRequest final
{
    std::uint64_t byte_size{0U};
    std::string declared_mime_type{};
    std::string sniffed_mime_type{};
    std::string content_hash{};
    bool scanner_clean{true};
};

} // namespace merovingian::media
