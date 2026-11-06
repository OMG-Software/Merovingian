// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/config/ClientApiConfig.hpp"
#include "merovingian/config/CorsConfig.hpp"
#include "merovingian/config/EmailConfig.hpp"
#include "merovingian/config/HttpTransportConfig.hpp"
#include "merovingian/config/IdentityServerConfig.hpp"
#include "merovingian/config/OidcConfig.hpp"
#include "merovingian/config/PushConfig.hpp"
#include "merovingian/config/SsoConfig.hpp"
#include "merovingian/config/TurnServerConfig.hpp"

#include <string>
#include <vector>

namespace merovingian::config
{

struct ServerConfig final
{
    std::string server_name{"example.org"};
    std::string public_baseurl{"https://matrix.example.org"};
    std::vector<std::string> trusted_proxies{};
    // CORS preflight policy. Wildcard `*` is the default origin and is safe
    // for Matrix because clients authenticate with `Authorization: Bearer`
    // tokens, not browser-credentialed cookies. A `*` in `allowed_origins`
    // combined with `allow_credentials=true` is rejected at config-parse
    // time per the CORS spec.
    CorsConfig cors{};
    // HTTP/1.1 persistent-connection (keep-alive) policy for the client and
    // federation listeners. See merovingian/http/keep_alive.hpp for the
    // semantics of each field; validation enforces the documented ranges.
    HttpTransportConfig http{};
    ClientApiConfig client_api{};
    // TURN relay configuration for GET /_matrix/client/v3/voip/turnServer.
    // Empty by default; when populated the endpoint returns real credentials.
    TurnServerConfig turn{};
    // OIDC discovery metadata. Empty by default; when populated the
    // auth_metadata endpoint advertises the configured OAuth 2.0 server.
    OidcConfig oidc{};
    // Identity Service API client config for 3PID invites/bind/unbind/
    // requestToken. Empty by default; with no trusted servers the homeserver
    // refuses 3PID operations that need an IS rather than minting locally.
    IdentityServerConfig identity_server{};
    // Push Gateway API delivery config. Disabled by default (see PushConfig).
    PushConfig push{};
    // SMTP relay for email pushers. Off by default (see EmailConfig).
    EmailConfig email{};
    // SSO login config. Disabled by default (see SsoConfig).
    SsoConfig sso{};
};

} // namespace merovingian::config
