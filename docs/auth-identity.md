# Authentication and identity foundation

This capability note describes the authentication and identity policy boundary
used before full Matrix Client-Server login, registration, and device APIs are
production-gated.

## Included now

- Matrix-shaped user ID validation.
- Server-name validation for local identity handling.
- Device ID validation.
- Password policy shape for future local-password authentication.
- Account state model for active, locked, and suspended users.
- Login policy decisions that fail closed for invalid, locked, or password-disabled accounts; suspended accounts MAY still log in per spec v1.19 §"Account suspension" (the new session is itself suspended and enforced by the request-path gate).
- Access-token record shape bound to user and device identity.
- Token hash persistence validation.
- Token expiry and revocation policy decisions.
- Constant-time string comparison helper for token-hash checks.
- Token redaction helper for safe logs.
- Runtime-wired server-blind E2EE key API route shapes for device keys,
  one-time keys, fallback keys, cross-signing, signatures, and room-key backup
  routes.
- Durable E2EE storage for device keys, one-time keys, fallback keys,
  cross-signing keys, signatures, backup versions, and backup sessions.
- `/keys/query` returns persisted device keys, and `/keys/claim` consumes
  one-time keys before reusing fallback keys.
- Redacted key payload summaries in runtime records and audit events.
- Client-server registration, password login, refresh-token rotation, logout,
  global logout, whoami, device listing, single-device fetch, device update,
  and device delete routes use runtime token validation.
- `POST /refresh` does not require access-token authentication — spec: "this
  endpoint does not require authentication via an access token. Authentication
  is provided via the refresh token." `client_auth_endpoint_requires_access_token`
  excludes `login`, `register_account`, and `refresh_token`.
- Account 3PID email and MSISDN flows are implemented across both the local and
  the IS-delegated surface. `POST /account/3pid/email/requestToken` and
  `POST /account/3pid/msisdn/requestToken` issue local validation sessions when no
  `id_server` is supplied (spec-conformant local validation), and delegate to a
  trusted remote identity server when both `id_server` and `id_access_token` are
  supplied — storing a `RegistrationValidationSession` keyed by the IS-issued
  `sid` so a later `bind` with the same `sid` + `client_secret` completes the
  association. `POST /account/3pid/add` enforces password UIA, the deprecated
  `POST /account/3pid` association route is accepted, and the bind/list/unbind/
  delete endpoints maintain per-account 3PID records including `added_at` /
  `validated_at` metadata plus, for IS-bound 3PIDs, the stored `client_secret` and
  `sid` (migration `007`) needed to drive a mode-2 remote unbind.
- Access-token hashes are durable and hydrate back into runtime sessions after
  restart.
- Refresh-token hashes are persisted, rotated, and revoked on global logout,
  device deletion, or password change with `logout_devices: true` (spec default)
  without storing plaintext token material; the caller's own device is preserved.
- Account lock/suspend admin endpoints `GET/PUT /_matrix/client/v1/admin/lock/{userId}`
  and `/_matrix/client/v1/admin/suspend/{userId}` (admin-gated, anti-enumeration,
  locality and self/other-admin guards) set the persisted and in-memory account
  state. The request path enforces spec semantics without revoking sessions: a
  locked account gets `401 M_USER_LOCKED` with `soft_logout: true` on all
  endpoints except `/logout` and `/logout/all`; a suspended account gets
  `403 M_USER_SUSPENDED` on actions outside the spec allowlist. Locked takes
  precedence over suspended.
- Login failures for unknown users, wrong passwords, and locked accounts
  collapse to the same external `invalid login` result while still recording
  the internal rejection reason in audit logs.
- Newly issued access and refresh tokens are persisted as keyed digests derived
  from the operator's master key file via domain-separated BLAKE2b. With a master
  key configured, issuance uses the `token-hash:v4:` scheme; the legacy
  `token-hash:v3:` scheme is retained only for validation and is itself now
  master-key-derived (distinct domain separator `merovingian:access-token-hmac:legacy-v3:1`)
  — it is no longer backed by the Ed25519 signing seed (issue #322, cryptographic
  key separation). **Breaking (v0.10.9):** pre-#322 `token-hash:v3:` hashes were
  derived from the Ed25519 signing seed and no longer validate under the new
  master-key-derived v3 key; affected sessions fail closed and must re-login,
  after which they are issued v4 tokens. Without a master key configured, both
  v3 and v4 are unavailable and issuance falls back to the unkeyed
  `token-hash:v2:` hash so local operations keep working — configure a master
  key for hardened token hashing (the federation worker already requires one).
  **(issue #436)** Every time a new token is issued under this fallback, a
  `token.unkeyed_hash_fallback` diagnostic is logged at `warning` so operators
  notice the degraded mode instead of discovering it in a post-breach audit
  (a DB leak of unkeyed v2 hashes is offline-brute-forceable).
- The v3 and v4 HMAC keys are derived from the master key file once and
  cached (`token_hmac_keys`, `src/homeserver/auth_service.cpp`) rather than
  re-read and re-derived on every request — every authenticated request
  previously performed two blocking reads of the operator's root secret and
  two `sodium_mlock`/`munlock` cycles. The cache is invalidated on the file's
  `(path, size, mtime)` identity, so replacing the master key still takes
  effect without a restart. See `docs/crypto-boundary.md` for why this
  matters as a crypto-boundary property, not just a performance one.
- `redacted_token_for_log()` (issue #437) discloses only a coarse size bucket
  (`tiny`/`short`/`medium`/`long`), never the exact byte length — the precise
  length was a minor side channel that let an observer of logs distinguish
  token versions and valid- from invalid-length presented tokens.
- Client-server auth/device/key actions append durable audit rows without
  logging plaintext credentials, bearer tokens, or key payloads.
- `GET /_matrix/client/v1/auth_metadata` (MSC2965 OIDC discovery) returns RFC 8414 / Matrix v1.19 authorisation server metadata when `server.oidc.*` is configured; returns `404 M_UNRECOGNIZED` when OIDC is not configured. No OAuth 2.0 authorization-code / token / revocation flow is implemented yet.
- **Application Service API identity (Matrix v1.19, `merovingian::appservice`).** Registration
  files (`appservice.registration_files`, parsed as JSON) build an in-memory
  `AppserviceRegistry` at startup; `as_token`/`hs_token` are held in a mlocked
  `core::SecretBuffer` and only ever compared via
  `crypto::constant_time_equal_variable_length`. A client-server request
  bearing a registered `as_token` authenticates as the appservice's own
  `sender_localpart` user by default, or as the user named by `?user_id=`
  when that user falls within one of the appservice's `users` namespaces
  (`403` otherwise); `?device_id=` must name a device already known to
  belong to the asserted user (`400 M_UNKNOWN_DEVICE` otherwise). This
  masquerade is resolved exactly once, at the top of
  `handle_client_server_request_impl`, by substituting `req.access_token`
  with an internal token (`appservice::encode_masquerade_token`,
  `appservice/masquerade_token.hpp`) that `authenticated_user`/
  `authenticated_session`/`authenticated_admin_user` in `auth_service.cpp`
  recognise and re-validate — never a real DB-backed session row, and never
  sent or logged. A raw client-presented token already in that internal
  shape is rejected before any auth logic runs, so the format cannot be
  forged from outside the process. `POST /register` and `POST /login` accept
  `type: m.login.application_service` (bearer-authenticated with `as_token`,
  restricted to the appservice's own namespace): registration is
  passwordless and bypasses UIA entirely per spec, and login mints an
  ordinary session with no password check, sharing the existing
  token-issuance path (`complete_login`) with `m.login.password`. An
  appservice's `exclusive` namespace blocks registration/alias creation by
  anyone else (`M_EXCLUSIVE`) — enforced in the registration and
  `PUT /directory/room/{roomAlias}` / `POST /createRoom` handlers. Outbound
  delivery to appservices (transactions, query hooks, `/thirdparty/*`) is
  not yet implemented — see `docs/todos/capability-gaps.md`.
- Unit coverage for identity validation, account lock/suspension behavior, password policy, token activity, and log redaction.
- Registration token verification using Argon2id (`crypto_pwhash_str` / `crypto_pwhash_str_verify`);
  only the password hash is retained, and the plaintext token is zeroised after hashing. The
  `GET /_matrix/client/v1/register/m.login.registration_token/validity` endpoint verifies the
  candidate through the same Argon2id hash (`registration_token_matches`) rather than comparing
  plaintext, so the token material never sits on the request path.
- Server-side access and refresh token expiry is enforced. `PersistentAccessToken`,
  `PersistentRefreshToken`, and `LocalSession` carry an `expires_at` field set at issuance from
  configurable `security.access_token_lifetime_ms` (default 1h) and
  `security.refresh_token_lifetime_ms` (default 30d); `0` disables expiry for that kind.
  `find_session` and the refresh-token lookup reject expired tokens (failing closed toward
  re-login/refresh) even when the session is not revoked, and the advertised `expires_in_ms`
  reads from the configured access-token lifetime so advertised == enforced. Legacy/no-expiry
  rows (`expires_at` empty / `nullopt`) remain valid.
- Token-hash lookups route through constant-time comparison (`crypto::constant_time_equal` /
  `auth::constant_time_equal`, backed by `sodium_memcmp`) on every fixed-length hash match —
  the access/refresh store lookups and the in-memory session match — not just the canonical
  policy helper.
- Device-list stream tokens and cross-device key update semantics: `build_device_list_arrays()`
  populates `/sync`'s `device_lists.changed`/`left` from `store.device_list_changes` filtered
  by `since_sync_stream_id` — through `sync::collect_device_list_delta()`, which reports each
  subject user once however many change rows the range covers, since both fields name users
  rather than change events — and `broadcast_device_list_updates()` emits `m.device_list_update`
  EDUs on cross-signing/key changes. Per-algorithm `device_one_time_keys_count` is wired into
  `/sync` as well. A `device_lists.changed` self-notification is recorded at two trigger points
  so a user's own devices discover each other without relying on room co-membership: on
  `POST /_matrix/client/v3/keys/upload` (key upload) and on `POST /_matrix/client/v3/login`
  when a genuinely new device is created. The login trigger ensures a freshly-logged-in
  device's initial `/sync` lists its own user in `device_lists.changed`, prompting it to
  `/keys/query` and fetch the user's *existing* devices' keys before any
  `m.key.verification.request` can arrive — closing the cross-device verification gap where
  the new device otherwise dropped the request for lack of the sender's device keys.
- Key-backup retrieval and deletion: `handle_key_api_route()` implements
  `get_key_backup_version`, `get_key_backup_version_by_id`, `get_room_key_backup`
  (session/room/batch), `get_room_key_backup_batch`, `delete_room_key_backup`,
  `delete_room_key_backup_room`, and `delete_room_key_backup_batch`, all reading/writing real
  session rows from `persistent_store.key_backup_sessions`.

## Identity server client (3PID invites)

A dedicated `identity` module (`include/merovingian/identity/identity_client.hpp`,
`src/identity/identity_client.cpp`) owns the outbound Identity Service API client.
`IdentityServerClient` exposes `store_invite`, `lookup`, `bind`, `unbind`, and
`requestToken` methods plus pure helpers (`parse_identity_server_url`,
`build_*_body`, `parse_store_invite_response`, `parse_lookup_response`). It talks
to a remote identity server over `http::OutboundClient` combined with
`federation::CachedServerDiscovery`, and is SSRF-safe: resolved addresses are
pinned and private/loopback ranges are rejected via `deny_ip_ranges`.

The homeserver is a **client** of the identity server, not a federation peer:
authentication uses a bearer `id_access_token` supplied by the calling client,
never `X-Matrix`. See spec v1.19 Identity Service API.

`POST /_matrix/client/v3/rooms/{roomId}/invite` with `id_server`/`medium`/
`address`/`id_access_token` now delegates token and key generation to the IS via
`store-invite` and builds the `m.room.third_party_invite` event from the
IS-issued token (used as the `state_key`) plus the IS's ephemeral public key
(top-level `public_key`/`key_validity_url`) and the full `public_keys` array.
Per spec v1.19 client-server-api §"Third-party invites" and the
`SignedThirdPartyInvite` shape, the token MUST be issued by the identity server
at `/store-invite`: the join-side `third_party_signed` signature is verified
against the IS's key, so the previous local-only token minting was
non-conformant. The HS fails closed with `403 M_FORBIDDEN` when the supplied
`id_server` is not listed in `server.identity_server.trusted_servers`, and
returns `502` on transport error or a malformed IS response.

The `server.identity_server.*` config block (`trusted_servers`,
`default_server`, `allowed_bind_domains`, `connect_timeout_seconds`,
`total_timeout_seconds`) is hot-reloaded and marked restart-required for
trust-set changes. 3PID bindings are persisted via migration
`006_account_threepids.sql` (previously in-memory); IS-bound bindings additionally
store the `client_secret` and `sid` needed for a remote unbind via migration
`007_account_threepids_columns.sql`.

### bind / unbind / requestToken IS delegation (v0.11.10)

The `bind`, `unbind`, and `requestToken` handlers now drive the remote IS when a
trusted `id_server` is supplied, not just persist locally:

- **`requestToken`** (`/account/3pid/email/requestToken`,
  `/account/3pid/msisdn/requestToken`, and the register/email, register/msisdn
  variants) — when both `id_server` and `id_access_token` are present and
  `id_server` is trusted, the HS resolves the trusted base URL, calls
  `IdentityServerClient::request_email_token` / `request_msisdn_token`, and on
  a 200 with an IS-issued `sid` stores a `RegistrationValidationSession` keyed by
  that `sid` (purpose `register` / `account-3pid`). The IS is the validation
  authority: it contacts the user by email/SMS and (optionally) redirects via
  `next_link`, so Merovingian has no client-facing `submitToken` for IS-delegated
  flows — the session completes when the client later calls `bind` with the same
  `sid` + `client_secret`. Absent `id_server` / `id_access_token`, the existing
  local-validation path is unchanged. Fail closed with `502` on transport error
  or a malformed IS response; `403` when `id_server` is not trusted.

- **`bind`** (`/account/3pid/add`, plus the deprecated `/account/3pid`) — after
  password UIA and the validation-session lookup, when `id_server` /
  `id_access_token` are supplied and trusted, the HS calls
  `IdentityServerClient::bind` over the held runtime mutex released for the
  network call, then persists `bound=true`, `id_server`, `client_secret`, and
  `sid`. The legacy `/account/3pid` route is extended to carry optional
  `id_server` / `id_access_token`; when absent it stays local-only for back-compat.

- **`unbind`** (`/account/3pid/delete`, `/account/3pid`) — the client sends no
  secret (spec-correct), so the HS recovers `client_secret` + `sid` from the
  stored binding and calls `IdentityServerClient::unbind` with an empty
  `id_access_token`. Per the IS API v2 this is **unbind auth mode 2**
  (`client_secret` + `sid`, no bearer) — `build_unbind_body` carries no
  `Authorization` header. Transport failure fails closed with `502`: silently
  removing the local binding while the IS still holds it would orphan the
  IS-side binding (the local `client_secret`/`sid` would be gone, making a retry
  impossible). A non-2xx IS response other than a recognised "no-support" shape
  also surfaces `502` so the user may retry; `id_server_unbind_result` reports
  `"success"` on 200 and `"no-support"` when the IS declines, removing the local
  record either way per spec (an operator trust-set change must not strand the
  3PID). When the stored binding has no `client_secret`/`sid`, the handler falls
  back to the existing local-only `threepid_unbind_result` logic.

All three flows reach the IS through the `test_forced_identity_resolution`
discovery seam (see `docs/http-transport.md`), which is empty in production —
production traffic resolves via the SSRF-safe `CachedServerDiscovery` path.

## OpenID tokens

`POST /_matrix/client/v3/user/{userId}/openid/request_token` (Matrix v1.19
CS API §OpenID) mints a narrow, short-lived bearer credential whose *only*
valid use is `GET /_matrix/federation/v1/openid/userinfo` (SS API §OpenID),
which a third-party service calls to learn the caller's Matrix user ID. This
is a fundamentally different trust level from an ordinary access token — an
access token authenticates the full client-server API; an OpenID token must
authenticate nothing beyond "who is this user" to one federation endpoint —
so it has its own, deliberately separate, lifecycle:

- **Separate table.** OpenID tokens live in `openid_tokens`
  (`migrations/010_openid_tokens.sql`, schema version 10), never
  `access_tokens`. See `docs/database-persistence.md` for the schema.
- **Separate mint path.** `homeserver::request_openid_token`
  (`src/homeserver/auth_service.cpp`) is the only function that writes to
  `openid_tokens`. It reuses the same keyed-hash machinery
  (`issue_token_hash`, preferring the master-key-derived v4 HMAC, falling
  back to v3/v2) access tokens use — sharing a well-reviewed hash function
  is not the same as sharing a trust boundary, and reusing it avoids a
  second, less-reviewed hashing path.
- **Separate lookup path.** `homeserver::federation_openid_userinfo` is the
  only function that reads `openid_tokens`. The ordinary client-server auth
  gate (`authenticated_user`, which backs every `Authorization: Bearer`
  check) only ever consults `access_tokens`/`database.sessions` and never
  looks at `openid_tokens`. Symmetrically, `federation_openid_userinfo`
  never consults `access_tokens`/`sessions`. Neither lookup path can
  accidentally accept the other token kind, because neither path ever reads
  the other table — the separation is structural, not a runtime check that
  could be bypassed or forgotten at a new call site.
- **Always finite expiry.** One hour from mint, hardcoded (not
  operator-configurable, unlike `access_token_lifetime_ms`): a longer-lived
  OpenID token still cannot reach the client-server surface, so the usual
  "shorten this to reduce blast radius" tradeoff for access tokens does not
  apply the same way here.
- **Fail-closed, indistinguishable rejection.** `GET /openid/userinfo`
  returns the identical `401 M_UNKNOWN_TOKEN` / "Access token unknown or
  expired" body whether the presented token was never issued or has expired
  — matching the spec's own error shape — so a caller cannot use the
  response to distinguish the two cases.
- **Unauthenticated redeem endpoint.** Per spec, `GET /openid/userinfo`
  requires no X-Matrix request signature and is not rate-limited: the caller
  may be any third-party service, not necessarily a homeserver. It is
  therefore dispatched outside the federation module's signed-request path
  entirely (`src/homeserver/local_http_router.cpp`,
  `federation_openid_userinfo_response`), alongside the same-shaped bypass
  for `GET /_matrix/key/v2/server`.
- **Retention.** `store_openid_token` sweeps every already-expired row
  (across all users) on each insert, so `openid_tokens` cannot grow without
  bound — see `docs/database-persistence.md`.

See `docs/threat-model.md` ("OpenID token confusion") for the
privilege-escalation risk this separation exists to prevent.

## SSO login

Matrix v1.19 CS API §"Client login via SSO" describes a six-step flow: a
client discovers `m.login.sso` via `GET /login`, sends the user's browser to
`GET /login/sso/redirect[/{idpId}]`, the homeserver redirects to an external
SSO system, that system authenticates the user and hands control back to the
homeserver, the homeserver mints a short-lived login token and redirects the
browser to the client's `redirectUrl` with `?loginToken=...`, and finally the
client exchanges that token for an access token via `POST /login` with
`type: m.login.token`.

Merovingian implements every homeserver-side piece of that flow **except**
the external SSO protocol itself (CAS/SAML/OIDC) — integrating a specific
external protocol is left to the operator's own SSO gateway, configured via
`server.sso.authorization_url`. What is implemented and enforced:

- **Config surface** (`config::SsoConfig`, `server.sso.*`): `enabled`
  (default `false`), `authorization_url` (the external SSO system's HTTPS
  entry point), `identity_providers` (a list of `{id, name, icon?, brand?}`
  — the spec's `IdP` shape, parsed from `server.sso.identity_providers.
  <idpId>.<name|icon|brand>` keys, `<idpId>` itself carrying the id), and
  `redirect_url_allowlist` (HTTPS URL prefixes a client's `redirectUrl` is
  validated against). Parse-time validation (`config::validate_config`)
  fails closed: `enabled = true` with an empty `authorization_url` or an
  empty `redirect_url_allowlist` is rejected outright, as is a duplicate or
  empty identity-provider `id`, an empty `name`, or a non-`mxc://` `icon`.
- **`GET /login` flow advertisement**: `m.login.sso` (with an
  `identity_providers` array when any are configured) is advertised only
  when `homeserver::sso_is_configured` holds — the same fail-closed
  condition the redirect endpoints check, shared through one function so
  the two paths cannot drift apart into "advertised but half-served" or
  vice versa.
- **`GET /login/sso/redirect[/{idpId}]`** (`homeserver::sso_redirect_target`):
  validates `redirectUrl` against `redirect_url_allowlist` (see
  `docs/threat-model.md`, "Open redirect and login-token exfiltration via
  SSO redirectUrl" — this is the control that keeps the endpoint from being
  an open redirect), validates `idpId` against the configured
  `identity_providers` when present (`404 M_NOT_FOUND` for an unrecognised
  IdP, per spec), and on success responds `302` with `Location` set to
  `authorization_url` carrying `idp`/`action`/`redirectUrl` query
  parameters through to the operator's external SSO system.
- **Completing the round trip** (`homeserver::complete_sso_login`): the
  integration point an operator's external SSO adapter calls once it has
  authenticated the user and mapped them to a local Matrix user id (spec
  steps 1-2 of "Handling the callback from the Authentication server" —
  identity mapping and, where applicable, JIT registration — are the
  adapter's responsibility, not Merovingian's, since they are inherently
  specific to the external protocol in use). It re-validates `redirectUrl`
  against the allowlist (never trust a value handed across an integration
  boundary a second time without re-checking it), mints a login token via
  the same `issue_token_hash` machinery access tokens use, persists it to
  the dedicated `login_tokens` table (never `access_tokens` — see
  "OpenID tokens" above for why that separation matters, and
  `docs/database-persistence.md` for the schema) with a fixed ~30-second
  expiry (spec: "SHOULD be limited to around five seconds" — Merovingian
  uses a slightly larger fixed window to tolerate real-world redirect
  latency without weakening the single-use guarantee that actually bounds
  the exposure), and returns `redirectUrl` with any pre-existing
  `loginToken` query parameters stripped (per spec step 4) and the new one
  appended.
- **`POST /login` with `type: m.login.token`**
  (`homeserver::redeem_login_token`): consults only the `login_tokens`
  table — deliberately independent of `authenticated_user`/`find_session`,
  mirroring `federation_openid_userinfo`'s structural separation from the
  access-token store — and consumes the token atomically
  (`database::consume_login_token`) so it cannot be redeemed twice. On
  success, session issuance (device-id validation, the account
  lock/suspend gate, access-token minting and persistence) is shared with
  password login via `homeserver::login_local_user_by_id`, the second half
  of `login_local_user` factored out so both callers get the exact same
  account-state enforcement — SSO login cannot bypass a locked or
  suspended account's gate just because it skipped the password check.
  Unknown, expired, and already-used tokens are indistinguishable to the
  caller (`403 M_FORBIDDEN`), matching how password login already
  collapses "unknown user" and "bad password" into the same external
  result.

## Account deactivation

`POST /_matrix/client/v3/account/deactivate` (Matrix v1.19 CS API §"Account
deactivation") is implemented. Previously this endpoint had no handler at
all — the path appeared only as a literal in the suspended-user allowlist —
so a user whose credentials were compromised had no way to close their own
account; only an admin-initiated lock or suspend existed, and both of those
are reversible where deactivation is not.

- **UIA**, exactly as `POST /account/password`: the request must carry a
  completed `m.login.password` auth stage proving current knowledge of the
  password. A missing, incomplete, or wrong-credential `auth` block returns
  the `401` UIA challenge, never `403`.
- **`homeserver::deactivate_local_user`** (`src/homeserver/auth_service.cpp`)
  marks the account permanently deactivated, revokes every access and
  refresh token for the user — including the caller's own, unlike a
  password change, since there is no session left worth preserving — and
  overwrites the password hash with the literal `!deactivated`, a value
  `auth::password_matches` can never match, so a credential leak predating
  deactivation cannot be replayed even if a future change were to soften the
  login gate.
- **The `users` row is retained**, not deleted: `deactivated` is a new
  column (schema version 14 — see `docs/database-persistence.md`), not a row
  removal, so registration's existing duplicate-`user_id` check keeps
  rejecting a re-registration of the same localpart.
- **Both login gates check it first.** `complete_login`'s shared tail and
  the token-login path in `login_local_user_by_id` (`src/homeserver/
  auth_service.cpp`) each reject `user.deactivated` with `403` "account
  deactivated" before evaluating the reversible `locked`/`suspended`
  states — deactivation outranks them because it is permanent where they
  are not.
- **`id_server_unbind_result`**, required in the `200` response body, is
  `"no-support"` when the account has any recorded 3PIDs and `"success"`
  when it has none. This server does not record which identity server
  bound each 3PID, and the spec names exactly that condition — "the
  homeserver being unable to determine an identity server to unbind
  from" — as the case for `no-support`.
- **Irreversible by design**: there is no reactivate endpoint.

**Not yet done**, tracked in `docs/todos/capability-gaps.md`: the request
body's `erase` parameter is parsed as part of the JSON body but never
inspected, so it has no effect either way — the spec's erasure behaviour is
a SHOULD, not a MUST, so this is not a conformance violation, but a client
that explicitly asks for erasure gets the same silent no-op as a client that
does not. The account's rooms are not left, and its 3PIDs are not unbound
from their identity servers as part of deactivation — only the local
account is marked deactivated and its tokens revoked.

## Per-account failed-login throttle

`/login` was previously throttled only per source IP, because the runtime
rate limiter's per-user tier keys on the *authenticated* user — someone who,
before a login succeeds, does not exist yet (see `docs/http-transport.md`
"Rate-limit policy"). Guesses against one account spread across many source
IPs therefore accumulated against nothing at all.

`login_local_user` (`src/homeserver/auth_service.cpp`) now tracks failures
against the *claimed* user ID, whether or not that user exists, so the
throttle cannot itself be used to probe which accounts are real: five
failures within a fifteen-minute window lock that claimed identity out for
fifteen minutes, returning `429`. Any successful login clears the account's
failure history. Tracking a claimed identity does mean a third party can
deliberately trip a real account's lockout — the standard account-lockout
trade-off — bounded by the window being fixed and short rather than
escalating or sticky, and by a real login clearing it immediately. The
thresholds (five failures, fifteen-minute window, fifteen-minute lockout)
are compile-time constants; exposing them as configuration is not done (see
`docs/todos/capability-gaps.md`).

## Security posture

The core auth policy module deliberately stays free of cryptographic password
hashing, token generation, and random number generation. The local homeserver
runtime now performs those operations through the reviewed LibSodium-backed
boundary rather than storing plaintext credentials or bearer tokens.

The boundary establishes these guarantees:

- Plaintext tokens are not a persistable representation.
- Token logging emits only redacted metadata.
- Revoked and expired tokens fail closed. Server-side token expiry is enforced on
  both access and refresh tokens via the configurable lifetimes above, distinct from
  revocation: an expired-but-not-revoked session is rejected with audit reason
  `token expired`.
- Locked accounts cannot pass the login policy gate; suspended accounts may
  still log in, and their new session is itself suspended and gated by the
  request-path `M_USER_SUSPENDED` check.
- Password login can be disabled per account.
- Device IDs reject whitespace/control-shaped values.
- Key API runtime records store route metadata and redacted payload summaries,
  not uploaded key material.
- Persisted key material is represented as server-blind sensitive JSON payloads
  and is not logged through prepared-statement summaries.
- Registration tokens are verified with Argon2id and only the hash is retained;
  plaintext tokens are zeroised with `sodium_memzero` after hashing.
- OpenID tokens (`POST /user/{userId}/openid/request_token`) are hashed and
  persisted in a table structurally disjoint from `access_tokens`, with
  disjoint mint and lookup paths, so they can never authenticate an ordinary
  client-server request — see "OpenID tokens" above.

## Deliberately not included

These remain deferred:

- Full Matrix UI-auth fallback flows and account recovery endpoints.
- Admin bootstrap flow.
- Rate-limit integration.

## Next starting points

1. Add a reviewed crypto dependency boundary for random token generation and password hashing.
2. Extend conformance fixtures beyond the beta auth/device/key happy paths into
   UI auth, interactive auth, and negative-device-list cases.

`/keys/upload` validates that every one-time and fallback key carries a signature by the
device's own Ed25519 identity key, rejecting unverifiable keys with `400 M_INVALID_SIGNATURE`.
This prevents stale device rows from leaving behind signed keys that no peer can verify at
`/keys/claim` time, which would block the Olm session for the whole room's Megolm distribution.
