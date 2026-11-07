// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::media
{

// ADR-0212: an mxc:// URI reserved by POST /_matrix/media/v1/create whose
// content has not been uploaded. Times are Unix milliseconds.
struct PendingMediaUpload final
{
    std::string media_id{};
    std::string owner_user_id{};
    std::uint64_t created_at_ms{0U};
    std::uint64_t expires_at_ms{0U};
};

} // namespace merovingian::media
