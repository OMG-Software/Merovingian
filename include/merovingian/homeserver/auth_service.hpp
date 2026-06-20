// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/auth/identity.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <optional>
#include <string>
#include <string_view>

namespace merovingian::homeserver
{

[[nodiscard]] auto register_local_user(HomeserverRuntime& runtime, std::string_view localpart,
                                       std::string_view password, std::string_view registration_token = {})
    -> OperationResult;
[[nodiscard]] auto bootstrap_admin_user(HomeserverRuntime& runtime, std::string_view localpart,
                                        std::string_view password) -> OperationResult;
[[nodiscard]] auto login_local_user(HomeserverRuntime& runtime, std::string_view user_id, std::string_view password,
                                    std::string_view device_id) -> OperationResult;
[[nodiscard]] auto issue_refresh_token_for_session(HomeserverRuntime& runtime, std::string_view user_id,
                                                   std::string_view device_id) -> OperationResult;
[[nodiscard]] auto refresh_local_session(HomeserverRuntime& runtime, std::string_view refresh_token)
    -> SessionRefreshResult;
[[nodiscard]] auto authenticated_user(HomeserverRuntime& runtime, std::string_view access_token)
    -> std::optional<std::string>;
[[nodiscard]] auto authenticated_session(HomeserverRuntime const& runtime, std::string_view access_token)
    -> std::optional<LocalSession>;
[[nodiscard]] auto authenticated_admin_user(HomeserverRuntime const& runtime, std::string_view access_token)
    -> std::optional<std::string>;
// Returns the account state (active/locked/suspended) of a server-local user,
// or std::nullopt if the user is unknown. Used by the request-path moderation
// gate in the client-server dispatcher to enforce M_USER_LOCKED / M_USER_SUSPENDED
// per spec v1.18 without revoking the user's access tokens.
[[nodiscard]] auto account_state_for_user(HomeserverRuntime const& runtime, std::string_view user_id)
    -> std::optional<auth::AccountState>;
[[nodiscard]] auto logout_local_user(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult;
[[nodiscard]] auto logout_all_local_user(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult;
[[nodiscard]] auto delete_local_device(HomeserverRuntime& runtime, std::string_view user_id, std::string_view device_id)
    -> OperationResult;
[[nodiscard]] auto change_local_user_password(HomeserverRuntime& runtime, std::string_view access_token,
                                              std::string_view new_password, bool logout_devices = true)
    -> OperationResult;
[[nodiscard]] auto verify_local_user_password(HomeserverRuntime& runtime, std::string_view access_token,
                                              std::string_view password) -> bool;
// Returns true when the presented access token exists in the session store but
// has expired naturally (not revoked). Used by the client-server auth gate to
// include soft_logout=true in the 401 body so clients use /refresh rather than
// clearing their session entirely (spec §5.7.2).
[[nodiscard]] auto access_token_is_soft_logout(HomeserverRuntime& runtime, std::string_view access_token) -> bool;

// Load the configured registration token from disk, Argon2id-hash it, and cache
// only the hash keyed by the file path. The plaintext token is zeroised after
// hashing. Returns std::nullopt when no token file is configured or it cannot be
// read/hashed. Exposed so the registration-token validity endpoint compares via
// the hash rather than holding the plaintext token on the request path.
[[nodiscard]] auto load_hashed_registration_token(config::RegistrationSecurityConfig const& registration)
    -> std::optional<std::string>;
// Constant-time verify a presented registration token against an Argon2id hash
// produced by load_hashed_registration_token (crypto_pwhash_str_verify).
[[nodiscard]] auto registration_token_matches(std::string_view expected_hash, std::string_view presented) noexcept
    -> bool;

} // namespace merovingian::homeserver
