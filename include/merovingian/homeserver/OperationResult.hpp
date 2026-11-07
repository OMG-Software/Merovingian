// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/MediaBodyStream.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::homeserver
{

struct OperationResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string value{};
    std::string reason{};
    // Milliseconds the caller should wait before retrying, for results that are
    // throttled rather than refused. Carried here so a 429 can be rendered as the
    // Matrix-standard M_LIMIT_EXCEEDED with retry_after_ms instead of collapsing
    // into the generic failure mapping, which would drop the delay this server
    // has already computed. Zero for every other outcome.
    std::uint32_t retry_after_ms{0U};
    // The Matrix errcode for a refusal the status alone cannot name, such as
    // 400 M_TOO_LARGE for an event over the spec's size limits (CSAZ-9). Empty
    // means the caller maps the status to its usual errcode.
    std::string errcode{};
    // R17: for a successful media download, the filename to serve in
    // Content-Disposition (the upload's, or the remote server's); empty when none.
    std::string media_filename{};
    // ADR-0574: for a successful download too large to hold, the stored bytes to send in chunks. `value` then
    // holds only the "content_type|" prefix, with no bytes after it.
    std::optional<MediaBodyStream> body_stream{};
};

} // namespace merovingian::homeserver
