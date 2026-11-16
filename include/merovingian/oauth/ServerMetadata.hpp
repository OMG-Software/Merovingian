// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/canonicaljson/Value.hpp"
#include "merovingian/oauth/OAuthBaseUrl.hpp"
#include "merovingian/oauth/ServerMetadataOptions.hpp"

namespace merovingian::oauth
{

// The OAuth 2.0 authorisation server metadata (RFC 8414) this server answers `GET /_matrix/client/v1/auth_metadata`
// with (spec "Server metadata discovery"), as a JSON object. Every address comes from `base` (issuer() and url() over
// the paths in OAuthPaths.hpp), so the document cannot name an endpoint the server does not route.
//
// Always present: `issuer`, `authorization_endpoint`, `token_endpoint`, `registration_endpoint`,
// `revocation_endpoint`, `response_types_supported` (`code`), `response_modes_supported` (`query`, `fragment`),
// `grant_types_supported` (`authorization_code`, `refresh_token`) and `code_challenge_methods_supported` (`S256`).
// The rest follows `options`.
[[nodiscard]] auto server_metadata(OAuthBaseUrl const& base, ServerMetadataOptions const& options)
    -> canonicaljson::Value;

} // namespace merovingian::oauth
