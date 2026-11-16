# The legacy SSO redirect hands off to the built-in pages, always confirms, and mints a 30-second login token

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: plan P10 in `docs/todos/oauth-2-0-api.md`, the hand-off for clients that know only the legacy API.

## Context and Problem Statement

With the OAuth 2.0 API on, the spec ("OAuth 2.0 aware clients", Server behaviour) requires the legacy `m.login.sso`
flow with `oauth_aware_preferred: true` and an `action` parameter on the SSO redirect. This server has no external
identity provider when OAuth is on (`server.sso.*` cannot be combined with it), so the redirect must lead to its own
sign-in pages and end, as the spec's "Client login via SSO" does, with a `loginToken` added to `redirectUrl`. A
`redirectUrl` is attacker-chosen: the spec's security considerations describe a link that sends a victim's login token
to `evil.com`. How should the redirect, the pages and the token be built?

## Decision Drivers

* A login token gives full access to the account; it must reach only an address the user agreed to.
* The `/authorize` machinery (browser cookie, Origin check, pending store and its per-address cap, the shared login
  throttle, `verify_password_login`, `create_local_account`) is already reviewed; a second copy would drift.
* No new persistent state, no migration.

## Considered Options

* Reuse `complete_sso_login` and its persistent `login_tokens` table.
* Mint into `LoginTokenStore` (`ClientServerRuntime::login_tokens`, the store `POST /login/get_token` uses) from a new
  kind of pending authorisation that the `/authorize` pages carry.
* Skip the confirmation for allowlisted addresses.

## Decision Outcome

Chosen option: the second, because it reuses every reviewed piece and holds the token only in memory, hashed.

* **One pending store, two kinds.** `PendingAuthorisation` carries `PendingAuthorisationKind`. The SSO redirect
  (`handle_login_hand_off`) creates a `login_token_hand_off` entry through the same `start_sign_in` the authorisation
  request uses, and the forms post to `/_merovingian/oauth2/authorize`. Only the consent page, `approve` and `deny`
  branch on the kind. A new kind is added the same way; never copy the handler.
* **The address rules** (`oauth::hand_off_redirect_target`): `https` with a host; `http` only on `localhost`,
  `127.0.0.1` or `[::1]`; a private-use scheme (one holding a `.`); nothing else. With
  `server.oauth.hand_off_redirect_allowlist` set, the address must also match an entry (ADR-0774); a loopback address
  matches none. A refused address is a 400 page with no `Location`. The entry stores the text, and the confirmation and
  `approve` read it again under the rules in force then.
* **Always confirm.** After the password, a page names the account and the destination (the host, or the scheme for an
  application on the device) and is sent with `page_headers(target)`, so its form may post only here and be answered
  by a redirect to that address. Even an allowlisted address is confirmed: the allowlist limits who can receive a
  token, the confirmation stops a link from spending the victim's session on a listed application.
* **The token.** `approve` judges the account again (`account_sign_in_gate`), mints 32 random bytes into
  `LoginTokenStore` under its caps with `hand_off_login_token_lifetime_ms` (30 seconds), audits
  `auth.login_token.issued` with reason `hand_off`, and answers 303 to `redirectUrl` with every `loginToken` parameter
  removed and the new one added (spec step 4), `no-store` and `no-referrer`. `deny` redirects nowhere.
* **Redeeming.** `POST /login` `m.login.token` redeems from `LoginTokenStore` when get_token is enabled or the hand-off
  is (`legacy_login_hand_off_enabled`). With the legacy API off, `POST /login` is refused before any token is read
  (ADR-0801), so no hand-off token is redeemable then.
* **The identity provider ID is not read.** `GET /login` lists no `identity_providers`, so `/redirect/{idpId}` starts
  the same pages for any ID.

### Positive Consequences

* No second login form, throttle or cookie; the per-address pending cap bounds how many hand-offs one address starts.
* A token never touches the database and is single use.

### Negative Consequences

* The token lifetime is 30 seconds, not the "around five seconds" the spec says a login token SHOULD be limited to:
  a native application on a phone must be switched to and send `POST /login`, which five seconds does not reliably
  allow. `complete_sso_login` already uses 30 seconds. The token is single use and bound to the user.
* `/redirect/{idpId}` with an unknown ID is served rather than answered 404.
* `complete_sso_login` stays without a caller while OAuth is on; it serves `server.sso.*` alone.

## Pros and Cons of the Options

### Reuse `complete_sso_login`

* Bad, because it requires `server.sso.*`, which cannot be configured with OAuth on.
* Bad, because it checks a different allowlist and writes the token to the database.

### Skip the confirmation for allowlisted addresses

* Good, because one click fewer.
* Bad, because a link to the redirect with a listed `redirectUrl` would then sign a victim's browser into an
  application the victim did not open, which the spec's security considerations warn of.
