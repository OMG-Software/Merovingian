// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string>

namespace merovingian::homeserver
{

// What an authorisation code stands for (plan "The authorisation flow", step 5): the approved request, bound to the
// user who approved it. The token endpoint (phase 6) checks the client, the redirect URI and the PKCE verifier against
// it before it writes a session.
struct AuthorizationGrant final
{
    std::string client_id{};
    // The redirect URI exactly as the authorisation request gave it.
    std::string redirect_uri{};
    // The PKCE `S256` challenge the token request's verifier must match.
    std::string code_challenge{};
    std::string user_id{};
    std::string device_id{};
    // The granted scope in canonical order.
    std::string scope{};
};

} // namespace merovingian::homeserver
