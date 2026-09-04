// SPDX-FileCopyrightText: 2026 James Chapman
// SPDX-License-Identifier: GPL-3.0-or-later
#pragma once

#include "merovingian/auth/identity.hpp"
#include "merovingian/config/config.hpp"
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
// Grants a session for an already-authenticated `user_id` -- the second
// half of login_local_user (device-id validation, account lock/suspend
// gate, token issuance/persistence, session bookkeeping) without a password
// check. Shared by login_local_user itself and by the `m.login.token`
// exchange (POST /login after redeem_login_token has already established
// the caller's identity via a redeemed SSO login token).
[[nodiscard]] auto login_local_user_by_id(HomeserverRuntime& runtime, std::string_view user_id,
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

// Permanently deactivates the account owning `access_token`: marks the user
// deactivated, revokes every access and refresh token including the caller's
// own, and replaces the password hash with an unmatchable value. Irreversible --
// there is deliberately no reactivate counterpart. The caller must have
// completed UIA before calling this.
[[nodiscard]] auto deactivate_local_user(HomeserverRuntime& runtime, std::string_view access_token) -> OperationResult;
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

// SSO login (Matrix v1.19 CS API §"Client login via SSO"). See
// docs/auth-identity.md for the full boundary: Merovingian routes and
// validates the redirect endpoints and the m.login.token exchange, but does
// not itself speak an external SSO protocol (CAS/SAML/OIDC) -- that lives
// behind the operator-configured `server.sso.authorization_url`.

// True when `server.sso.*` is complete enough to serve the SSO flow at
// all: enabled, with an authorization_url to redirect to, and at least one
// redirectUrl allowlist entry so the redirect endpoints are not
// unconditionally rejecting. Config-parse validation already enforces this
// invariant for anything read from disk (see config::validate_config), but
// both the `GET /login` flow advertisement and the redirect handlers below
// call this rather than re-deriving the condition, so the two paths cannot
// silently drift apart -- fail closed consistently rather than twice.
[[nodiscard]] auto sso_is_configured(config::SsoConfig const& sso) noexcept -> bool;

// Outcome of resolving `GET /login/sso/redirect[/{idpId}]` to a concrete
// redirect target. `location` is only meaningful when `ok` is true.
struct SsoRedirectResult final
{
    bool ok{false};
    std::uint16_t status{400U};
    std::string location{};
    std::string errcode{};
    std::string reason{};
};

// Validates the request against `server.sso.*` and, on success, builds the
// URI the browser should be 302-redirected to. Fails closed (ok=false) when:
// SSO is disabled/misconfigured (`M_UNRECOGNIZED`, 404 -- the endpoint does
// not exist as far as the client can tell); `idp_id` is non-empty but not
// one of the configured identity providers (`M_NOT_FOUND`, 404, matching
// spec's documented response for an unrecognised IdP); or `redirect_url` is
// empty or not covered by `server.sso.redirect_url_allowlist`
// (`M_INVALID_PARAM`, 400) -- this last check is the control that prevents
// the endpoint from being an open redirect.
[[nodiscard]] auto sso_redirect_target(HomeserverRuntime const& runtime, std::string_view idp_id,
                                       std::string_view redirect_url, std::string_view action) -> SsoRedirectResult;

// Completes an SSO authentication for `user_id`: mints a short-lived,
// single-use login token (persisted in `login_tokens`, never
// `access_tokens` -- see PersistentLoginToken), and returns `value` set to
// the final `redirectUrl?loginToken=...` the browser should be sent to next
// (spec steps 4-5). This is the integration point an operator's external
// SSO adapter calls once it has verified the user's identity and mapped it
// to a local Matrix user id. `redirect_url` is re-validated against
// `server.sso.redirect_url_allowlist` (never trust a caller-supplied value
// across an integration boundary without re-checking it).
[[nodiscard]] auto complete_sso_login(HomeserverRuntime& runtime, std::string_view user_id,
                                      std::string_view redirect_url) -> OperationResult;

// Redeems a login token minted by complete_sso_login, for `POST /login`
// with `type: m.login.token` (spec step 6). Consumes the token so it cannot
// be redeemed twice, and returns the owning Matrix user id, or std::nullopt
// if the token is unknown, expired, or already used -- these are
// deliberately indistinguishable to the caller.
[[nodiscard]] auto redeem_login_token(HomeserverRuntime& runtime, std::string_view login_token)
    -> std::optional<std::string>;

} // namespace merovingian::homeserver
