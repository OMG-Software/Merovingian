// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>
#include <vector>

namespace merovingian::config
{

// `server.oauth.*`: the built-in OAuth 2.0 API (ADR-0812, ADR-0816). Off by default. Its addresses are not configured:
// every one is derived from `server.public_baseurl` (ADR-0773). validate() refuses each non-default value of the last
// three fields unless `enabled` is true, so a configuration cannot half-enable the API.
struct OAuthConfig final
{
    // Serves the OAuth 2.0 API: the metadata at `auth_metadata` and, in later phases, its endpoints and pages.
    bool enabled{false};
    // With false the legacy login and registration API refuses new user sessions (ADR-0813).
    bool legacy_api_enabled{true};
    // Serves the device authorization grant (RFC 8628), off by default because it lets an attacker start a login
    // and send the victim the link.
    bool device_grant_enabled{false};
    // Where the hand-off from the legacy SSO redirect may send the browser: `https` origins and bare private-use
    // schemes, never URL prefixes (ADR-0774). Empty: any target, after the confirmation page.
    std::vector<std::string> hand_off_redirect_allowlist{};
};

} // namespace merovingian::config
