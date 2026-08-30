// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/auth/identity.hpp"
#include "merovingian/homeserver/runtime.hpp"

#include <cstdint>
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
                                    std::string_view device_id, bool with_ttl = false) -> OperationResult;
// Application Service API (Matrix v1.19): see the .cpp definitions for the
// full spec citation. The caller MUST have already verified the presented
// as_token and that the target user_id/localpart is within the appservice's
// namespace (or is its own sender_localpart) before calling either of these
// — neither function re-derives that check itself.
[[nodiscard]] auto register_appservice_user(HomeserverRuntime& runtime, std::string_view localpart) -> OperationResult;
[[nodiscard]] auto login_appservice_user(HomeserverRuntime& runtime, std::string_view user_id,
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

// Outcome of an `/_merovingian/admin/*` auth gate. `user_id` is set when the
// presented token belongs to a confirmed admin; otherwise `denial` identifies
// which HTTP response applies — `missing_token` for a missing/expired/unknown
// token (401 M_MISSING_TOKEN/M_UNKNOWN_TOKEN) and `not_admin` for a valid
// token whose user is not an admin (403 M_FORBIDDEN). This splits the two
// cases `authenticated_admin_user` collapses, so admin routes match the
// `/_matrix/client/v3/admin/*` status-code convention (spec v1.19).
struct AdminAuthResult
{
    enum class Denial : std::uint8_t
    {
        none,
        missing_token,
        not_admin,
    };
    std::optional<std::string> user_id{};
    Denial denial{Denial::none};
};
[[nodiscard]] auto require_admin(HomeserverRuntime& runtime, std::string_view access_token) -> AdminAuthResult;

// Returns the account state (active/locked/suspended) of a server-local user,
// or std::nullopt if the user is unknown. Used by the request-path moderation
// gate in the client-server dispatcher to enforce M_USER_LOCKED / M_USER_SUSPENDED
// per spec v1.19 without revoking the user's access tokens.
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

// Result of minting an OpenID token via `POST
// /_matrix/client/v3/user/{userId}/openid/request_token` (Matrix v1.19 CS
// API §OpenID). Kept separate from OperationResult because the spec's 200
// response has three required fields beyond the token itself.
struct OpenidTokenIssueResult final
{
    bool ok{false};
    std::uint16_t status{500U};
    std::string access_token{};
    std::string matrix_server_name{};
    std::uint64_t expires_in_seconds{0U};
    std::string reason{};
};

// Mints a short-lived OpenID token for `user_id`. The token is stored in the
// dedicated `openid_tokens` table -- NEVER the access-token store -- so it
// cannot be used to authenticate ordinary client-server requests (see
// federation_openid_userinfo for the matching separation on the redeem
// side; docs/threat-model.md documents the token-confusion risk this
// prevents). The caller is responsible for verifying the path userId
// matches the authenticated caller before calling this: this function does
// not re-check identity, only that user_id is well-formed enough to hash
// and persist.
[[nodiscard]] auto request_openid_token(HomeserverRuntime& runtime, std::string_view user_id) -> OpenidTokenIssueResult;

// Redeems an OpenID token minted by request_openid_token, returning the
// owning Matrix user ID, or std::nullopt if the token is unknown, expired,
// or malformed. Used by `GET /_matrix/federation/v1/openid/userinfo`
// (Matrix v1.19 SS API §OpenID). Deliberately consults only the
// openid_tokens table -- an ordinary client-server access token is always
// rejected here, even if it happens to collide byte-for-byte, because the
// lookup never touches the access-token/session store.
[[nodiscard]] auto federation_openid_userinfo(HomeserverRuntime const& runtime, std::string_view openid_access_token)
    -> std::optional<std::string>;

} // namespace merovingian::homeserver
