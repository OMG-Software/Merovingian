// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::media
{

struct LocalMediaUploadResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string media_id{};
    std::string content_uri{};
    std::string content_type{};
    std::uint64_t size_bytes{0U};
    std::string hash_algorithm{};
    std::string digest{};
    bool deduplicated{false};
    bool quarantined{false};
    std::string reason{};
};

} // namespace merovingian::media
