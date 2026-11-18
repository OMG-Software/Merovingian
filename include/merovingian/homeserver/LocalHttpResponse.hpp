// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/MediaBodyStream.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace merovingian::homeserver
{

struct LocalHttpResponse final
{
    std::uint16_t status{500U};
    std::string body{};
    // Per-response headers. CORS preflight responses fill this with
    // `Access-Control-Allow-*` and `Vary: Origin`; `format_response` writes
    // the contents to the wire in insertion order, with the standard
    // `Content-Length` / `Content-Type` / `Connection: close` lines emitted
    // automatically.
    std::vector<std::pair<std::string, std::string>> headers{};
    // The Matrix errcode for a failure, carried from OperationResult::errcode so
    // the client API can return it rather than one guessed from the status.
    // Internal only: never written to the wire by format_response.
    std::string errcode{};
    // A media download's stored upload filename (ADR-0211), for the client API
    // to put in Content-Disposition. Internal only, like errcode: a field, not a
    // header, so no caller that writes `headers` to the wire can leak it.
    std::string media_filename{};
    // ADR-0574: when set, `body` is empty and the HTTP layer sends these bytes, read from the database in chunks
    // as it writes, with Content-Length set to `size_bytes`.
    std::optional<MediaBodyStream> body_stream{};
    // An OAuth 2.0 HTML page (ADR-0785), built with `oauth::page_headers`. A page is served to the browser at its own
    // origin and never read cross-origin, so the client-server boundary adds no CORS header to it
    // (`apply_client_response_headers` adds only `X-Content-Type-Options`), and nothing downstream rewrites it: the
    // client API's `wrap()` of a router answer returns a page unchanged. Internal only, never written to the wire.
    bool page{false};
};

} // namespace merovingian::homeserver
