// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::media
{

// A download with its bytes, as the federation media endpoint returns it.
struct LocalMediaDownloadResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string content_type{};
    std::string bytes{};
    std::string reason{};
    // The `filename` the upload was made with; empty when there was none. Sent in the
    // media part's Content-Disposition so the requesting server can serve it (R17).
    std::string upload_name{};
};

} // namespace merovingian::media
