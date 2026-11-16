// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::homeserver
{

// The session an OAuth 2.0 authorization code grant writes (grant_oauth_session, ADR-0792): what the redeemed code
// was bound to, after the token endpoint matched the client, the redirect URI and the PKCE verifier.
struct OAuthGrantRequest final
{
    std::string user_id{};
    std::string device_id{};
    std::string client_id{};
    // The granted scope, as the code holds it.
    std::string scope{};
    // The display name of a device the grant creates: the client's registered name, or empty for none.
    std::string display_name{};
    // The `oauth_sessions` row's `created_at_ms`, from AuthorizationCodeStore::next_session_created_at_ms, so the code
    // can name the row it produced.
    std::uint64_t created_at_ms{0U};
};

} // namespace merovingian::homeserver
