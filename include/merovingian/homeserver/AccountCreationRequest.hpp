// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace merovingian::homeserver
{

// An account to create without a session (`create_local_account`, ADR-0783). Borrowed views: the caller keeps the
// strings alive for the call.
struct AccountCreationRequest final
{
    // The desired localpart, already chosen (POST /register generates one when the client named none).
    std::string_view localpart{};
    // The password as typed. Never logged.
    std::string_view password{};
    // The registration token the caller presented, or empty.
    std::string_view registration_token{};
    // The client key the registration policy judges (`trust_safety::RegistrationPolicyRequest::requester_address`,
    // which refuses an empty one). POST /register passes "127.0.0.1", as it always has; the OAuth 2.0 account page
    // passes `rate_limit_client_key`.
    std::string_view client_key{};
};

} // namespace merovingian::homeserver
