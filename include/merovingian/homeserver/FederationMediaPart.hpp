// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::homeserver
{

// Result of parsing a 200 response from the authenticated federation media
// download endpoint. Per spec the response is always `multipart/mixed` with
// exactly two parts: an (currently always empty) JSON metadata part, and
// either the media bytes or a `Location` redirect header. `ok` is false when
// the response could not be parsed as a well-formed two-part multipart body.
// `is_redirect` is true when the second part carries a `Location` header
// instead of inline bytes; `location` is only populated in that case.
struct FederationMediaPart final
{
    bool ok{false};
    bool is_redirect{false};
    std::string content_type{};
    std::string bytes{};
    std::string location{};
    // R17: the filename in the media part's Content-Disposition, if any.
    std::string filename{};
};

} // namespace merovingian::homeserver
