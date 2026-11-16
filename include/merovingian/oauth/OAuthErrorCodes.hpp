// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace merovingian::oauth
{

// The OAuth 2.0 `error` codes this module answers with. They are wire values (RFC 6749 section 5.2, RFC 7591
// section 3.2.2), sent as the `error` member of a JSON body or the `error` parameter of a redirect; an
// OAuthRefusal carries one of them.
inline constexpr std::string_view error_invalid_request = "invalid_request";
inline constexpr std::string_view error_invalid_grant = "invalid_grant";
inline constexpr std::string_view error_invalid_scope = "invalid_scope";
inline constexpr std::string_view error_invalid_redirect_uri = "invalid_redirect_uri";
inline constexpr std::string_view error_invalid_client_metadata = "invalid_client_metadata";

} // namespace merovingian::oauth
