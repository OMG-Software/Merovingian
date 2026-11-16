// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>

namespace merovingian::homeserver
{

// What a pending authorisation ends in once its user signed in and approved (ADR-0802).
enum class PendingAuthorisationKind : std::uint8_t
{
    // An OAuth 2.0 authorisation request: the consent page, then an authorization code sent to the client's matched
    // redirect URI (ADR-0787 to ADR-0790).
    authorization_code,
    // The legacy SSO redirect's hand-off: the confirmation page, then a login token added to the `redirectUrl` the
    // hand-off accepted (`oauth::hand_off_redirect_target`). No client is registered for it.
    login_token_hand_off,
};

} // namespace merovingian::homeserver
