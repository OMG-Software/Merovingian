# A UIA endpoint refuses an OAuth session, and the cross-signing upload follows the spec's exemptions

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 6 of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md) (proposal P7)

Amended by [ADR-0797](0797-an-oauth-session-replaces-its-cross-signing-keys-through-the-m-oauth-stage-and-a-one-use-approval.md):
a replacing `POST /keys/device_signing/upload` from an OAuth session is offered the `m.oauth` stage instead of the 403.

## Context and Problem Statement

A session from the OAuth 2.0 API has no password the client may be asked for: the user typed it on this server's
page, never into the client. The spec has User-Interactive Authentication use the `m.oauth` stage for such a session,
which sends the user to the account management page. This server has no account management page yet. What does a UIA
endpoint answer an OAuth session?

Separately, `POST /keys/device_signing/upload` always asked for UIA here, but since v1.11 the spec exempts an upload
when no master key is held or when every uploaded key matches the held one, and since v1.17 an application service. An
OAuth client (Element X) uploads its first keys right after signing in.

## Considered Options

* Offer the `m.oauth` UIA stage now.
* Answer 403 `M_FORBIDDEN` with a fixed message naming `OAuthBaseUrl::url(account_path)`, until the account page exists.
* Keep asking for `m.login.password`, which an OAuth client cannot answer.

## Decision Outcome

Chosen option: the second, with the spec's exemptions for the cross-signing upload.

* `oauth_session_uia_refusal` (`ClientServerRuntime.cpp`) is asked first by every handler that asks for UIA with an
  access token: `POST /login/get_token` (after its enabled check), `POST /account/password`, `POST /account/deactivate`,
  `POST /account/3pid/add`, `DELETE /devices/{deviceId}` and `POST /delete_devices`. It answers for a session whose
  device has an `oauth_sessions` row, before the body is read and before a UIA session is issued; never for an
  application service (a masquerade token), which the spec exempts. A new UIA endpoint asks it too.
* `POST /keys/device_signing/upload` asks `cross_signing_upload_is_uia_exempt` first: an application service, a user
  with no master key, or a request whose master key and every other key are byte for byte the canonical JSON held needs
  no UIA, for every session. Only the remaining case, a change to held keys, asks `oauth_session_uia_refusal` and then
  the password stage.
* When the account page lands, the `m.oauth` stage replaces the 403 (a superseding ADR).

### Negative Consequences

* An OAuth session cannot change its password, deactivate the account, add an email address, delete a device or
  replace its cross-signing keys until the account page lands. The message says where it will be.
* A token holder can now upload the first cross-signing keys of an account that has none without the password, as the
  spec allows.
