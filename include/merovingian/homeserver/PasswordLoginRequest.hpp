// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <string_view>

namespace merovingian::homeserver
{

// A password to verify for a login (`verify_password_login`, ADR-0783). Borrowed views: the caller keeps the strings
// alive for the call.
struct PasswordLoginRequest final
{
    // The full user ID, as `login_identifier_user_id` makes it from what the user typed (POST /login does the same).
    std::string_view user_id{};
    // The password as typed. Never logged.
    std::string_view password{};
    // The rate-limit client key of the caller (`rate_limit_client_key`): failures are counted per (account, source).
    std::string_view client_source{};
    // The device the login is for, as the log and audit lines name it. Not validated or created here.
    std::string_view device_id{};
};

} // namespace merovingian::homeserver
