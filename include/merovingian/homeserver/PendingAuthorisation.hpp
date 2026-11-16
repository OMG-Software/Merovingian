// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/homeserver/PendingAuthorisationKind.hpp"
#include "merovingian/oauth/ResponseMode.hpp"

#include <cstdint>
#include <optional>
#include <string>

namespace merovingian::homeserver
{

// A validated authorisation request (`GET /_merovingian/oauth2/authorize`) waiting for the user to log in or register
// and then approve or deny it (plan P5, ADR-0782). `PendingAuthorisationStore` holds it in memory under the hash of a
// random identifier, bound to the browser by the hash of a cookie value.
//
// Every field but the last three is the request as the handler validated it, never repaired. The store sets
// `created_at_ms` and `client_address_key` from its own arguments and starts `user_id` empty.
struct PendingAuthorisation final
{
    // What the entry ends in. A hand-off (`login_token_hand_off`, ADR-0802) has no client: `client_id`, `state`,
    // `code_challenge`, `device_id`, `scope` and `login_hint` stay empty.
    PendingAuthorisationKind kind{PendingAuthorisationKind::authorization_code};
    // The registered client that asked.
    std::string client_id{};
    // The redirect URI exactly as the request gave it (a native loopback URI keeps the port it was sent with); it was
    // matched against the registration with `oauth::match_redirect_uri` before the entry was made. For a hand-off,
    // the `redirectUrl` `oauth::hand_off_redirect_target` accepted.
    std::string redirect_uri{};
    oauth::ResponseMode response_mode{oauth::ResponseMode::query};
    // The client's `state`, returned with the answer. Empty when the client sent none.
    std::string state{};
    // The PKCE `S256` challenge, checked with `oauth::pkce_challenge_is_valid`.
    std::string code_challenge{};
    // The device ID the scope names, and the granted scope in canonical order (`oauth::parse_scope`).
    std::string device_id{};
    std::string scope{};
    // Whether the request asked for account creation (`prompt=create`).
    bool create_account{false};
    // The client's `login_hint`, if any. Shown only as escaped text and never trusted.
    std::optional<std::string> login_hint{};
    // The user whose password was verified on the login or registration page; empty until then.
    std::string user_id{};
    // The rate-limit client key of the browser that made the request (`rate_limit_client_key`).
    std::string client_address_key{};
    // When the store took the entry, in milliseconds since the epoch.
    std::uint64_t created_at_ms{0U};
};

} // namespace merovingian::homeserver
