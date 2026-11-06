// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::media
{

// Body and outer Content-Type for a v1.19 federation media download response.
// The body is a multipart/mixed envelope with an empty JSON metadata part and
// a second part carrying the media bytes.
struct FederationMediaDownloadBody final
{
    std::string body{};
    std::string content_type{};
};

} // namespace merovingian::media
