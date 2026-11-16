// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/LocalHttpResponse.hpp"

#include <optional>

namespace merovingian::core
{
class FormFields;
} // namespace merovingian::core

namespace merovingian::homeserver
{

struct LocalHttpRequest;

// Module-internal: the refusal of a request to the token or revocation endpoint that carries client credentials, or
// nullopt when it carries none. Every client of this server is public (ADR-0791), so credentials are never accepted:
// an `Authorization` header with the `Basic` scheme (any case, RFC 9110 section 11.1) is 401 `invalid_client` with
// `WWW-Authenticate: Basic`, which RFC 6749 section 5.2 requires when the client tried that header; a `client_secret`
// field is 400 `invalid_client`. Logs nothing.
[[nodiscard]] auto oauth_client_credentials_refusal(LocalHttpRequest const& request, core::FormFields const& fields)
    -> std::optional<LocalHttpResponse>;

} // namespace merovingian::homeserver
