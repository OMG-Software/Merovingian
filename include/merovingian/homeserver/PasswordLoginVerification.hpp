// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include <cstdint>
#include <string>

namespace merovingian::homeserver
{

// What `verify_password_login` found (ADR-0783). The outcomes are exactly what POST /login tells a client apart, and
// nothing more: an unknown user, a wrong password, a password changed during the hash, and a locked account are all
// `invalid_login`, as /login answers each of them `403 M_FORBIDDEN "invalid login"`. A suspended account is
// `verified`: /login lets it log in (spec v1.19 "Account suspension").
struct PasswordLoginVerification final
{
    enum class Outcome : std::uint8_t
    {
        // The password is the account's, and the account may log in: `user_id` names it.
        verified,
        // /login's `403 M_FORBIDDEN "invalid login"`.
        invalid_login,
        // The failed-login throttle refused before the password was looked at: /login's `429 M_LIMIT_EXCEEDED "too
        // many failed login attempts"` with `retry_after_ms`.
        throttled,
        // No Argon2id admission slot was free: /login's `429 M_LIMIT_EXCEEDED "too many concurrent authentication
        // attempts"` with `retry_after_ms`. Not a failed attempt.
        busy,
        // The account is deactivated: /login's `403 M_FORBIDDEN "account deactivated"`.
        account_deactivated,
    };

    Outcome outcome{Outcome::invalid_login};
    // The verified user; empty unless `outcome` is `verified`.
    std::string user_id{};
    // For `throttled` and `busy`: milliseconds until a retry may succeed. Zero otherwise.
    std::uint32_t retry_after_ms{0U};
};

} // namespace merovingian::homeserver
