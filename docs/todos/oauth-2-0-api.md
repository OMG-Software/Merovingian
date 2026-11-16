# OAuth 2.0 API plan (1.1.0)

This is the working plan for branch `feature/oauth-20-v110`. It is removed when the last phase lands: what
outlives the work goes to `auth-identity.md`, `http-transport.md`, `threat-model.md`, `user-manual.md` and the ADR
register, as the update table in `docs/AGENTS.md` requires.

## Why

Element X creates accounts only through the Matrix OAuth 2.0 API. It asks `GET /_matrix/client/v1/auth_metadata`,
gets `404 M_UNRECOGNIZED` from Merovingian, and tells the user that the account provider "needs to be upgraded to
support Matrix Authentication Service and account creation". Password login from Element X still works; account
creation, and everything else Element X does through the OAuth 2.0 API, does not.

The spec added the OAuth 2.0 API in v1.15 beside the legacy API
([Client Authentication](../matrix-v1.19-spec/client-server-api.md#client-authentication),
[OAuth 2.0 API](../matrix-v1.19-spec/client-server-api.md#oauth-20-api)). A server may offer either or both. Under
it a client never registers or logs a user in itself: it sends the browser to pages the homeserver serves.

## Decisions

### Made by the owner (2026-11-15)

| Decision | Record |
|---|---|
| The OAuth 2.0 API is built into the homeserver. Nothing is delegated to an external authorisation server. | [ADR-0760](../adr/0760-the-oauth-2-0-api-is-built-into-the-homeserver.md) |
| The legacy login and registration API stays on by default. A config key turns it off. | [ADR-0761](../adr/0761-the-legacy-authentication-api-stays-on-by-default-and-a-config-key-turns-it-off.md) |
| The registration page applies the legacy registration settings: the enabled flag and the registration token. | [ADR-0762](../adr/0762-the-registration-page-applies-the-legacy-registration-settings.md) |
| The pages are built into the binary: fixed HTML, no JavaScript, no template files. | [ADR-0763](../adr/0763-the-authentication-pages-are-built-into-the-binary-without-javascript.md) |
| `server.oauth.*` replaces `server.oidc.*`. A config that sets `server.oidc.*` is refused at start-up. | [ADR-0764](../adr/0764-server-oauth-replaces-server-oidc-and-the-old-keys-are-refused.md) |
| 1.1.0 holds the core flow, the account pages, the hand-off for legacy clients and the device authorization grant. | This plan |

### Proposed here, to be confirmed in review

Each becomes an ADR in the phase that implements it. The phase must not start until the owner has seen the row.

| # | Proposal | Reason | Phase |
|---|---|---|---|
| P1 | The issuer is `server.public_baseurl`. Endpoints and pages live under `/_merovingian/oauth2/` and `/_merovingian/account`. | The spec fixes only `auth_metadata`; the rest is advertised. A namespace this server owns cannot collide with `/_matrix/` or a site at `/`. | 2 |
| P2 | A client ID is a keyed hash of the accepted client metadata. | Clients register again before every login. The same metadata then yields the same row, so the table does not grow per login (the spec allows it). | 4 |
| P3 | An OAuth session is a row in a new `oauth_sessions` table keyed by (user, device). The token tables are not changed. | v1 token tables are frozen and some of their inserts are positional. A device is an OAuth device or it is not; the tokens need no new column. | 3 |
| P4 | Access and refresh tokens are the existing opaque tokens, with the existing lifetimes and rotation. | Reuse detection, rotation and the lost-response retry already match the spec (ADR-0074, ADR-0590). | 6 |
| P5 | Authorization codes, pending authorisations and device codes are held in memory, hashed, bounded and single use. | They live for seconds or minutes. A restart ends a login in progress and nothing else. `LoginTokenStore` is the model. | 5, 10 |
| P6 | There is no long-lived browser session. An authorisation asks for the password every time. The account pages keep a session for 15 minutes. | No standing cookie to steal, and no "already signed in" path to get wrong. | 5, 8 |
| P7 | An endpoint that needs user-interactive authentication answers an OAuth session `403 M_FORBIDDEN`, naming the account page. Application services are exempt. | The spec says such endpoints cannot be used with an OAuth token. It names no error. | 6 |
| P8 | Revoking either token ends the session and deletes the device, as `POST /logout` does. | The spec makes revocation the OAuth logout. It does not say what becomes of the device. | 7 |
| P9 | With the legacy API off, sessions it issued earlier keep working, `/refresh` and `/logout` included, until they end. | Turning a key off must not sign every user out. | 9 |
| P10 | The hand-off for legacy clients always shows a confirmation page naming where the browser is sent next. An optional allowlist restricts it further. | The redirect target comes from the request and receives a login token. | 9 |
| P11 | The device authorization grant has its own key and is off by default. | It lets an attacker start a login and send the victim the link. An operator should choose it. | 10 |

## What Element X needs

Read from the Element X and matrix-rust-sdk sources on 2026-11-15, through a summarising fetch. Phase 11 confirms
each row against a real client.

| Need | Source |
|---|---|
| `auth_metadata` answers 200 and passes validation: `https` on every URL, an issuer with no query or fragment, `code` in `response_types_supported`, `query` and `fragment` in `response_modes_supported`, `authorization_code` and `refresh_token` in `grant_types_supported`, `S256` in `code_challenge_methods_supported`, and a `revocation_endpoint`. Any failure is reported to the user as "no OAuth support". | matrix-rust-sdk `authentication/oauth`, ruma `get_authorization_server_metadata` |
| A `registration_endpoint` that accepts `token_endpoint_auth_method: none` and answers JSON with a `client_id`. | matrix-rust-sdk `oauth/registration.rs` |
| The iOS redirect URI is a claimed `https` link on the host of its `client_uri`, not a custom scheme. | element-x-ios `AppSettings.swift` |
| Scopes `urn:matrix:client:api:*` and `urn:matrix:client:device:<id>`, the stable forms, with a device ID the client generates. | matrix-rust-sdk `oauth/mod.rs` |
| PKCE with `S256`. `prompt=create` for account creation when `prompt_values_supported` holds `create`, otherwise `prompt=consent`. A `login_hint` may be present. | element-x-ios `AuthenticationService.swift` |
| A refresh token in every token response. Logout revokes the access token at `revocation_endpoint`. | matrix-rust-sdk `oauth/mod.rs` |

Not verified, and treated as open until phase 11: Android's redirect URI and `application_type`; whether the SDK
asks the stable or the unstable `auth_metadata` path first; which `response_mode` it sends; how it reads
`expires_in`; where Element X uses `account_management_uri`.

Element X's QR-code login also needs a rendezvous API (MSC4108) that is not in spec v1.19. This plan implements the
device authorization grant the spec defines. It does not make Element X's QR-code login work, and the owner decides
separately whether to add the rendezvous API.

## What the spec requires

The requirements below are the ones the design turns on. The section anchors are in
[the local spec copy](../matrix-v1.19-spec/client-server-api.md#oauth-20-api).

- **Metadata** (`#get_matrixclientv1auth_metadata`): `issuer`, `authorization_endpoint`, `token_endpoint`,
  `registration_endpoint`, `revocation_endpoint` and the four `*_supported` lists are required. `prompt_values_supported`,
  `device_authorization_endpoint`, `account_management_uri` and `account_management_actions_supported` are optional.
- **Client registration** (`#client-registration`): unauthenticated, RFC 7591. The server MUST support
  `application_type` `web` and `native`, MUST support `token_endpoint_auth_method: none`, MUST ignore grant and
  response types it does not know, and MUST validate redirect URIs. It answers `201` with the `client_id` and the
  metadata it registered. It MUST NOT delete a registration that has an active session.
- **Redirect URIs** (`#redirect-uri-validation`): never a fragment. `web`: `https`, no userinfo, on the host of
  `client_uri` or a subdomain of it. `native`: a private-use scheme that is the reverse of the `client_uri` host with
  no authority, or `http` on `localhost`, `127.0.0.1` or `[::1]` registered without a port and matched with any
  port, or a claimed `https` URI under the `web` rules.
- **Authorization code grant** (`#authorization-code-grant`, `#login-flow`): PKCE `S256`, a pre-registered redirect
  URI matched exactly, `state` returned on success and on failure, and `response_mode` `query` or `fragment`.
- **Scope** (`#scope`): `urn:matrix:client:api:*` and exactly one `urn:matrix:client:device:<device_id>`. The client
  chooses the device ID. If the user already holds that device, its earlier tokens are invalidated.
- **Refresh** (`#refresh-token-grant`): the server MUST issue a refresh token with every grant, the access token MUST
  be short-lived, a used refresh token SHOULD be replaced, the client MUST be able to retry a refresh whose answer was
  lost, and reuse of a replaced token SHOULD end the session.
- **Revocation** (`#token-revocation`): the server MUST revoke the access and the refresh token of the token it is
  given, SHOULD do so even when `client_id` is missing or wrong, and answers `200` for a token that is already invalid.
- **User-interactive authentication** is not available to an OAuth session. The one exception is
  `POST /keys/device_signing/upload`, which offers the `m.oauth` stage with a URL to the account page
  (`#oauth-authentication`).
- **Account management** (`#account-management`): optional. Actions `org.matrix.profile`,
  `org.matrix.devices_list`, `org.matrix.device_view`, `org.matrix.device_delete`,
  `org.matrix.account_deactivate` and `org.matrix.cross_signing_reset`, with a `device_id` parameter.
- **Device authorization grant** (`#device-authorization-grant`): optional, RFC 8628. `prompt=create` does not apply.
- **Application services** (`#post_matrixclientv3register`): `POST /register` MUST keep working for them when the
  legacy API is off, and answers `400 M_APPSERVICE_LOGIN_UNSUPPORTED` unless `inhibit_login` is `true`.
- **OAuth 2.0 aware clients** (`#oauth-20-aware-clients`): the server offers `m.login.sso` with
  `oauth_aware_preferred: true`, keeps `m.login.password` if it was offered before, and reads `action=login` or
  `action=register` on the SSO redirect endpoints.
- **OAuth endpoints use OAuth rules**, not Matrix ones: form-encoded requests, and errors as `error` and
  `error_description`.

The spec leaves these to the server: every page, the registration policy, the token format and lifetimes, the
lifetime of a code, rate limits, and what a revocation does to the device.

## Design

### Configuration

| Key | Default | Meaning |
|---|---|---|
| `server.oauth.enabled` | `false` | Serves the OAuth 2.0 API and its pages. |
| `server.oauth.legacy_api_enabled` | `true` | With `false`, the legacy login and registration endpoints refuse new logins (ADR-0761). Refused unless `server.oauth.enabled` is `true`. |
| `server.oauth.device_grant_enabled` | `false` | Serves the device authorization grant (P11). |
| `server.oauth.hand_off_redirect_allowlist` | empty | Restricts where the legacy hand-off may send the browser (P10). |

- `server.oidc.*` is refused at start-up with a message naming `server.oauth.enabled` (ADR-0764).
- With `server.oauth.enabled`, `server.public_baseurl` must be an `https` URL with no userinfo, query or fragment.
  The metadata is generated from it; no endpoint URL is configured. One function builds every absolute URL.
- `server.sso.authorization_url` and `server.oauth.enabled` together are refused: the built-in pages answer the SSO
  redirect in phase 9.
- Registration through the page is governed by `security.registration.*` and nothing else (ADR-0762).
  `prompt_values_supported` holds `create` only while `security.registration.enabled` is `true`.
- Token lifetimes are `security.access_token_lifetime_ms` and `security.refresh_token_lifetime_ms` (P4).

### Routes

| Route | Method | Purpose |
|---|---|---|
| `/_matrix/client/v1/auth_metadata` | GET | Metadata. Also served at `/_matrix/client/unstable/org.matrix.msc2965/auth_metadata`, with the same document. |
| `/_merovingian/oauth2/register` | POST | Client registration, JSON. |
| `/_merovingian/oauth2/authorize` | GET, POST | The authorisation request, then the login, registration and consent forms. |
| `/_merovingian/oauth2/token` | POST | Code, refresh and device-code grants, form-encoded. |
| `/_merovingian/oauth2/revoke` | POST | Revocation, form-encoded. |
| `/_merovingian/oauth2/device` | POST | Device authorization request (phase 10). |
| `/_merovingian/oauth2/link` | GET, POST | Where the user types a device code (phase 10). |
| `/_merovingian/account` | GET, POST | Account pages (phase 8). |

Every route needs what `src/homeserver/AGENTS.md` lists under "Adding a new client-server endpoint": a handler ahead
of the 405 and 404 gates, a `static_routes` entry, a `client_static_route_allow` row naming every method, a row in
`tests/conformance/test_route_query_conformance.cpp`, and a rate-limit tier. All of them take the `auth_sensitive`
tier except `auth_metadata`, which the spec marks not rate-limited and stays in the generic tier (ADR-0775). `auth_metadata`, the registration, token, revocation and device endpoints carry the CORS headers; the pages
carry none.

### Module layout

- **`src/oauth/` and `include/merovingian/oauth/`**: a new module of pure functions with no runtime state. It holds
  the metadata builder (`ServerMetadata`, which replaced `auth/OidcDiscovery`), client metadata and redirect URI validation, the scope
  parser, PKCE verification and the page renderer. It gets an `AGENTS.md`, a `CLAUDE.md` and rows in the root
  `AGENTS.md`.
- **`src/core/`**: a strict `application/x-www-form-urlencoded` parser (a malformed escape or a repeated parameter
  is an error, unlike `parse_query_params`) and a `Cookie` header parser.
- **`src/homeserver/`**: the handlers and the stores that hold runtime state: pending authorisations, codes, device
  codes, the client table, the account-page sessions and the cross-signing reset approvals. Everything runs under
  `runtime.mutex` and is bounded by the request.
- **`src/database/`**: the two new tables, their row types, store functions and hydration.

### Storage (migration 002)

This is the first migration after the frozen v1 schema, so the phase also does what `migrations/AGENTS.md` requires
of the first one: `initial_schema_definitions()` keeps the v1 shape and `current_schema_definitions()` gains the
change.

| Table | Columns | Notes |
|---|---|---|
| `oauth_clients` | `client_id` (key), `metadata_json`, `created_at_ms`, `last_used_at_ms` | Capped. The retention sweep deletes a client with no session and no use for 30 days. A client with a session is never deleted. |
| `oauth_sessions` | `user_id`, `device_id` (key together), `client_id`, `scope`, `created_at_ms` | Written in the transaction that writes the device and its tokens. Deleted with the device. |

Both tables are classified as never read by the federation worker
(`tests/unit/test_worker_table_load_profile.cpp`, `docs/database-persistence.md`).

1.1 is also where the cross-release upgrade fixture returns (`tests/fixtures/upgrade/README.md`): the last 1.0.x
release writes a database, and `tests/integration/test_database_upgrade_flow.cpp` proves that this branch opens,
migrates and serves it on SQLite and on PostgreSQL.

### The authorisation flow

1. **Request.** `GET /authorize` is checked in this order: the client exists; `redirect_uri` matches a registered
   one exactly (a loopback URI with any port); then `response_type`, `scope`, the PKCE challenge, `response_mode`
   and the device ID. A failure of the first two renders an error page and never redirects. Any later failure
   redirects with `error` and `state`.
2. **Pending authorisation.** The validated request is stored in memory under a random ID, for 10 minutes. The ID
   travels in a hidden form field. A `__Host-` cookie (`Secure`, `HttpOnly`, `SameSite=Lax`) binds it to the browser,
   and each form carries a token checked against the cookie.
3. **Login or registration.** `prompt=create` shows the registration form when registration is enabled, otherwise
   the login form with a notice. Login goes through the login failure throttle and the Argon2id admission budget
   exactly as `POST /login` does. Registration calls `register_local_user`, so every existing check applies.
4. **Consent.** The page names the client, the host of its `client_uri`, where the browser goes next, the device ID
   and what is granted (the whole account). Client metadata is attacker-chosen text: it is escaped, logos are never
   fetched, and host names are shown in their ASCII form.
5. **Code.** Approval mints a code: 32 random bytes, stored as a hash, single use, 60 seconds, bound to the client,
   redirect URI, challenge, user, device and scope. The browser is redirected with `code` and `state` in the query or
   the fragment. Denial redirects with `error=access_denied`.
6. **Token.** `POST /token` with `grant_type=authorization_code` checks the client, the redirect URI and the PKCE
   verifier, then writes the device, the access token, the refresh token and the `oauth_sessions` row in one
   transaction. A code presented twice revokes the session it produced.

### Tokens, refresh and revocation

- An OAuth session is an ordinary `LocalSession` whose device has an `oauth_sessions` row. Every existing gate
  (deactivated, locked, suspended, device cap, cross-signing key ID collision) applies unchanged.
- `grant_type=refresh_token` calls `refresh_local_session` after checking that the device is an OAuth device of the
  presented client. Legacy `POST /refresh` refuses an OAuth device's token, and the token endpoint refuses a legacy
  one: the two APIs do not mix.
- The response gives `expires_in` in seconds. A refused refresh is always a 4xx, because the client treats a 5xx as
  "try again" and a 4xx as "signed out".
- Revocation finds the session by either token and ends it as `logout_local_user` does (P8). An unknown token is
  `200`. Tokens are compared in constant time and never logged.

### Pages

Every page is fixed HTML rendered by one function that accepts only escaped fragments (ADR-0763). Every page sends
`Content-Security-Policy` (`default-src 'none'`, a hashed inline style, `frame-ancestors 'none'`),
`X-Frame-Options: DENY`, `Referrer-Policy: same-origin` and `Cache-Control: no-store`. A page that posts a form
checks `Origin` and `Sec-Fetch-Site` with `oauth::form_post_origin_is_accepted` (ADR-0784).

### Account pages and the `m.oauth` stage

`/_merovingian/account` asks for the password, then keeps a 15-minute session in a `__Host-` cookie with
`SameSite=Strict`. It lists devices, shows one, deletes one, changes the password, deactivates the account and
approves a cross-signing reset. Each action calls the service function the client API already uses
(`delete_device_and_announce`, `deactivate_user_account` with `finish_account_deactivation`); the password change is
`change_password_on_account_page`, the email reset's core, because `change_local_user_password` keeps a calling device
the page does not have (ADR-0798). Deactivation asks for the password again. `account_management_actions_supported`
lists exactly the actions that are implemented: all six. Done in phase 8 (ADR-0796 to ADR-0798).

A cross-signing reset approval is a per-user flag, in memory, valid for 10 minutes and spent by one upload.
`POST /keys/device_signing/upload` from an OAuth session that would replace existing keys answers `401` with the
`m.oauth` stage and the account page URL, and accepts the retry once the flag is set. The approval is taken by the
retry and given back unless the keys are stored (ADR-0797).

### The legacy API beside OAuth

- With both APIs on, `GET /login` adds `m.login.sso` with `oauth_aware_preferred: true`. The SSO redirect endpoints
  read `action` and send the browser to the built-in login or registration page. After the confirmation page (P10)
  the browser returns to the client with a login token, which the client redeems with `m.login.token`. This gives
  `complete_sso_login` its first caller.
- With `server.oauth.legacy_api_enabled=false`: `GET /login` is `404 M_UNRECOGNIZED`; `POST /login` and
  `POST /register` refuse users; `POST /register` still serves application services and requires
  `inhibit_login: true`; `m.login.application_service` is `400 M_APPSERVICE_LOGIN_UNSUPPORTED`. Existing legacy
  sessions carry on (P9).

### Device authorization grant

`POST /device` answers a device code (secret, stored as a hash), a user code of 8 characters from a 20-letter
alphabet shown as `XXXX-XXXX`, `verification_uri`, `verification_uri_complete`, `expires_in` 600 and `interval` 5.
The user opens `/_merovingian/oauth2/link`, types the code, logs in and consents on the same pages as above; the
consent page says plainly that another device is being signed in. The token endpoint answers `authorization_pending`,
`slow_down`, `access_denied` or `expired_token` until then. Wrong user codes are counted per client address and
throttled. The table is in memory and capped.

## Phases

Each phase ends in a commit that builds and passes the suite on the Linux VM. Phases 2 and 3 are independent of
each other; within phase 1 the pieces are independent. Everything else is in order.

| # | Phase | Delivers | Done when |
|---|---|---|---|
| 0 | Branch and plan | Version 1.1.0, this plan, ADR-0760 to ADR-0764. | The tooling tests for the version, the changelog and the docs site pass. |
| 1 | Foundations | `oauth` module skeleton; form and cookie parsers; page renderer and escaping; PKCE; scope parser; redirect URI and client metadata validation; `302` and `303` reason phrases. | Unit tests for each, with the spec's valid and invalid redirect URI examples as cases. Fuzz targets for the parsers and validators. |
| 2 | Configuration and metadata | `server.oauth.*`; refusal of `server.oidc.*`; the stricter `public_baseurl`; generated metadata on both paths. | `auth_metadata` passes the checks under "What Element X needs". Example configs and `test_example_config.py` updated. |
| 3 | Storage | Migration 002, the schema split, both tables, hydration on both backends, worker classification, the retention pass, the 1.0.x upgrade fixture. | The upgrade scenarios pass on SQLite and PostgreSQL. |
| 4 | Client registration | `POST /register` with the validation rules, deterministic IDs (P2) and the cap. | Conformance scenarios for every MUST in `#client-registration`. A flood of distinct registrations cannot evict a client that has a session or a pending authorisation. |
| 5 | Authorisation | Pending authorisations, the login, registration and consent pages, the code. Password verification split out of `login_local_user`. | An integration test drives the pages with an HTTP client and receives a code. Throttle and admission tests cover the page login. |
| 6 | Token endpoint | Code and refresh grants; the one-transaction session write; the rules that keep the two APIs apart (P7). | Code, verifier, redirect and client mismatches are each refused. Code reuse revokes. A lost refresh response can be retried. |
| 7 | Revocation | `POST /revoke`. | Either token ends the session and removes the device. An unknown token is 200. |
| | **Milestone A** | | **Element X on iOS and Android creates an account, logs in, syncs and logs out against the VM.** |
| 8 | Account pages | The six actions, password change, and the `m.oauth` stage. | Each action is tested through the page. A cross-signing reset from an OAuth session succeeds only after approval. |
| 9 | Legacy API | The operator switch and the hand-off for OAuth 2.0 aware clients. | Both settings of the switch are covered for users and for application services. A legacy client completes a hand-off login. |
| 10 | Device grant | The device endpoint, the link page and the device-code grant. | Polling answers follow RFC 8628. User-code guessing is throttled. |
| 11 | Close | `threat-model.md`, `security-review-checklist.md`, the owning guides, `capability-gaps.md`, the review skill; a review with `.agent/skills/merovingian-review/`; the suite on the Linux and FreeBSD VMs; the Element X checks left open above. | Every row of "Risks" is closed or accepted by the owner. This file is deleted. |

Tests follow `testing-standards.md`: pure logic in `tests/unit/`, anything that drives
`handle_client_server_request` in `tests/integration/`, and every MUST of the spec section as a conformance
scenario citing it.

## Risks and traps

| Risk | Handling |
|---|---|
| A page is new attack surface: cross-site request forgery, clickjacking, script injection through client metadata, login forgery. | No JavaScript, one renderer, the headers under "Pages", a per-form token, `Origin` checks. The threat model gains a section in phase 11. |
| Chromium applies the `form-action` directive to the redirect that follows a form post, so a strict policy blocks the final redirect to the client. | The consent page's policy must allow the redirect target. Test the flow in a Chromium-based browser in phase 5. |
| An open redirect, or a code sent to the wrong party. | No redirect before the client and the redirect URI are validated; exact matching; PKCE; a code bound to its client and redirect URI. |
| Unauthenticated registration fills the client table. | Deterministic IDs, a body cap, a table cap, the `auth_sensitive` rate limit, and eviction only of clients with no session and no pending authorisation. |
| Work under `runtime.mutex`. | Every table is bounded and indexed; no scan per request; Argon2id through the admission budget with the lock released, then re-validation (`src/auth/AGENTS.md`). |
| Secrets in logs. | Codes, tokens, device codes and the query string of `/authorize` are never logged. New audit events name the client and the user only. |
| `format_response_head` matches `Content-Type` by exact case and `reason_phrase` knows neither 302 nor 303. | Fixed in phase 1. |
| Login today writes the session and the refresh token in two transactions, so a failed second write answers 500 after the login committed. | The OAuth path writes all of it in one transaction (phase 6). The legacy path is left as it is. |
| `register_local_user` passes the policy engine a fixed source address. | The page passes the client key. Whether to change the legacy route is the owner's call; it is reported, not changed here. |
| A device code phished from a victim. | Off by default (P11); the consent page names the client and says another device is signing in. |
| Element X behaviour that was inferred, not verified. | The open items under "What Element X needs" are checked at Milestone A, before phases 8 to 10 build on them. |
