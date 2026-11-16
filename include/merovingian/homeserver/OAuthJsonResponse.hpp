// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/homeserver/LocalHttpResponse.hpp"
#include "merovingian/oauth/OAuthRefusal.hpp"

#include <cstdint>
#include <string_view>

namespace merovingian::homeserver
{

// The answers of the OAuth 2.0 JSON endpoints (registration, token, revocation; ADR-0781). They follow OAuth rules,
// not Matrix ones: an error is `{"error": ..., "error_description": ...}` (RFC 6749 section 5.2, RFC 7591 section
// 3.2.2), never a Matrix `errcode`, and every answer carries `Content-Type: application/json` and
// `Cache-Control: no-store`, because a registration or token answer must never be stored by a cache. CORS headers are
// added at the dispatcher's boundary like every other client-server answer.

// `body` serialised as canonical JSON with `status`. A body the serialiser refuses (which only a defect can build)
// becomes a 500 `server_error` with a fixed description.
[[nodiscard]] auto oauth_json_response(std::uint16_t status, canonicaljson::Value const& body) -> LocalHttpResponse;

// The error answer of `refusal` with `status`: its `error_code` as `error` and its fixed message as
// `error_description`. The message never quotes the request (oauth/AGENTS.md rule 2), so it is safe to send.
[[nodiscard]] auto oauth_error_response(std::uint16_t status, oauth::OAuthRefusal const& refusal) -> LocalHttpResponse;
// The same for a refusal written at the call site: `error_code` (one of oauth/OAuthErrorCodes.hpp) and a fixed
// `description` that never quotes the request.
[[nodiscard]] auto oauth_error_response(std::uint16_t status, std::string_view error_code, std::string_view description)
    -> LocalHttpResponse;

// An answer with no body and `Cache-Control: no-store`: the 200 of a revocation request (RFC 7009 section 2.2: "The
// content of the response body is ignored by the client"; ADR-0795). No `Content-Type`, since there is no content.
[[nodiscard]] auto oauth_empty_response(std::uint16_t status) -> LocalHttpResponse;

} // namespace merovingian::homeserver
