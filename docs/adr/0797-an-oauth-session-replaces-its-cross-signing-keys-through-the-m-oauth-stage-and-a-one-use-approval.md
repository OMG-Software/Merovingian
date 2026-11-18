# An OAuth session replaces its cross-signing keys through the m.oauth stage and a one-use approval

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 8 of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md). Amends
[ADR-0794](0794-a-uia-endpoint-refuses-an-oauth-session-and-cross-signing-upload-follows-the-spec-exemptions.md) for
`POST /keys/device_signing/upload`.

Amended by [ADR-0799](0799-the-m-oauth-stage-accepts-a-polling-retry-without-a-session-and-reuses-the-user-s-live-session.md)
(2026-11-16): with a live approval a retry with no `auth`, or no `session`, also completes the stage; the challenge
reuses the user's live session and offers `org.matrix.cross_signing_reset` as a second flow. The decision below is
otherwise unchanged.

Amended by [ADR-0809](0809-a-cross-signing-reset-approval-is-bound-to-the-oauth-device-that-asked-for-it.md) (2026-11-16): the
challenge URL carries the requesting device, and an approval given on a page that named one of the user's OAuth devices
is spent only by that device's upload.

## Context and Problem Statement

ADR-0794 refused every UIA endpoint to an OAuth session with 403 until the account pages existed. The spec's
`m.oauth` stage ("OAuth authentication") is valid only on `/keys/device_signing/upload`: the server answers 401 with
`m.oauth` in `flows` and `params["m.oauth"].url`, the user confirms in the account management web UI, and the client
completes the stage with an `auth` dict holding just the `session`. What does "confirms" record, how long does it
last, and what may use it?

## Decision Drivers

* A stolen access token alone must not replace a user's cross-signing identity.
* One confirmation must not authorise more than one replacement.
* A refused or failed upload must not use up the user's confirmation.
* A password session must never be satisfied by the account page, and an OAuth session never by a password.

## Considered Options

* A per-user approval in memory, 10 minutes, spent by exactly one stored upload, completed with a real UIA session.
* An approval bound to the UIA session ID shown in the URL.
* Accept any upload for a few minutes after the approval.

## Decision Outcome

Chosen option: the first.

* A replacing upload (not `cross_signing_upload_is_uia_exempt`) from a session `oauth_session_uia_refusal` names is
  answered `401` with exactly:
  `{"flows":[{"stages":["m.oauth"]}],"params":{"m.oauth":{"url":"<account_management_uri>?action=org.matrix.cross_signing_reset"}},"session":"<id>"}`,
  the session issued with `issue_uia_session` for the purpose `cross_signing_reset` and the user (a full pool is 429).
* The account page's reset form records `CrossSigningResetApprovals::approve` for the signed-in user (10 minutes,
  replacing any earlier one; 4096 users at most) and audits `cross_signing.reset_approved`.
* A retry with a session this server issued to this user for that purpose, whose `type` is absent or `m.oauth`, takes
  the approval (`take`) inside the request. Any other `type` (a password stage) gets the same challenge and its
  password is never checked. Without an approval it gets the same challenge and session.
* The taken approval is held by `TakenResetApproval`, which gives it back (`restore`) on every way out except a stored
  upload: a refusal by `cross_signing_upload_refusal`, a key named like a device, or a failed store keeps the
  approval. `spend()` runs only after `store_key_api_payload` succeeds, and audits `cross_signing.reset_used`.
  `runtime.mutex` serialises the take and the store, so two concurrent uploads cannot both use one approval.
* A password (legacy) session keeps the `m.login.password` flow and never reads or spends an approval.
* With OAuth off, or no usable `public_baseurl`, the OAuth session keeps ADR-0794's 403.
* Every password change, reset and deactivation withdraws the user's approval (ADR-0798).

### Negative Consequences

* The approval is per user, not per client: any of the user's OAuth sessions may use it within the 10 minutes. The
  account page's text says the permission is used by one reset.
* A restart forgets every approval; the user approves again.

## Pros and Cons of the Options

### An approval bound to the UIA session ID in the URL

* Good, because it ties the approval to one request.
* Bad, because the spec's URL carries only `action` (and `device_id`): the page would need a parameter the spec does
  not define, and the session ID would sit in a URL the user's browser keeps in its history.

### Accept any upload for a few minutes

* Bad, because one confirmation would authorise any number of replacements.

## Links

* Amends [ADR-0794](0794-a-uia-endpoint-refuses-an-oauth-session-and-cross-signing-upload-follows-the-spec-exemptions.md)
* Uses the session of [ADR-0796](0796-the-account-pages-keep-a-fixed-15-minute-session-in-memory-bound-to-a-strict-cookie-and-a-form-token.md)
