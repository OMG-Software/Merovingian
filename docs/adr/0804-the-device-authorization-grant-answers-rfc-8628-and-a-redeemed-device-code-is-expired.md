# The device authorization grant answers RFC 8628, and a redeemed device code is expired

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: plan P11 and phase 10 in `docs/todos/oauth-2-0-api.md`.

## Context and Problem Statement

The spec makes the device authorisation grant optional and defers to RFC 8628. The plan serves it only when
`server.oauth.device_grant_enabled` is true (P11). RFC 8628 leaves several answers to the server: what a second poll
after the tokens were issued hears, how long a denied code is remembered, how `slow_down` is measured, what a full
store answers, and whether `verification_uri_complete` may sign in without the user confirming the code. Each choice
looks arbitrary in the code, and a later change could quietly make the grant easier to abuse.

## Decision Drivers

* The grant lets an attacker start a sign-in and send a victim the link (plan "Risks"). Nothing a device or a link
  does may skip the user's own confirmation.
* A device code is a bearer secret until it is redeemed, and must be redeemed once.
* RFC 8628 section 3.5: `slow_down` adds five seconds "for this and all subsequent requests".
* The token endpoint is in the `auth_sensitive` rate-limit tier (20 a minute per address, ADR-0775).

## Considered Options

For a second poll after the tokens were issued:

* `expired_token`, as for any code the store does not hold.
* `invalid_grant`, as the code grant answers a replayed code.
* Ending the session the first poll created, as a replayed authorization code does (ADR-0792).

## Decision Outcome

* **Routes and switch.** `POST /_merovingian/oauth2/device` and `GET`/`POST /_merovingian/oauth2/link` are answered
  before the access-token gate and are `404 M_UNRECOGNIZED` unless `server.oauth.enabled` and
  `server.oauth.device_grant_enabled` are both true. The token endpoint answers the grant type
  `urn:ietf:params:oauth:grant-type:device_code` only then; otherwise `unsupported_grant_type`. The metadata names
  the endpoint and the grant only then.
* **The device endpoint** takes a registered client that lists the device grant (`invalid_client`,
  `unauthorized_client` otherwise), the spec scope (`parse_scope`), and answers `device_code`, `user_code` (shown as
  `XXXX-XXXX`), `verification_uri`, `verification_uri_complete`, `expires_in` 600 and `interval` 5, with the CORS
  headers and `Cache-Control: no-store`. A full store, in all or for the address, is `503 temporarily_unavailable`
  (RFC 6749 section 4.1.2.1 as the registration cap answers, ADR-0780); a random-source failure is `500
  server_error`.
* **The poll's checks are in order**: `client_id` and `device_code` present (`invalid_request`), the client registered
  (`invalid_client`) and for the grant (`unauthorized_client`), then the store: an unknown, expired or redeemed code is
  `expired_token`; another client's code is `invalid_grant`; a denied code is `access_denied`, at every poll until it
  expires; an approved code is redeemed once; a poll sooner than the interval after the previous poll is `slow_down`,
  which grows the interval by five seconds for good; otherwise `authorization_pending`. The first poll is never
  `slow_down`. Every refusal is 400; a failed session write is `500 server_error`.
* **A second poll after the tokens were issued is `expired_token`.** The store removes an approved entry when it hands
  it out, so a redeemed code is indistinguishable from an unknown one. Chosen over ending the session: a device code
  is polled from one device by design, and a retry after a lost answer is the likely cause of a second poll, not
  theft; the device can sign in again. Chosen over `invalid_grant`: RFC 8628 says a device code that can no longer be
  used is `expired_token`.
* **An approval goes through the same session write as the code grant** (`grant_oauth_session`, ADR-0792), after
  `account_sign_in_gate` judges the account again: a user locked, suspended or deactivated between the approval and
  the poll gets no session (`invalid_grant`).
* **`verification_uri_complete` only prefills the code.** `GET /link` looks nothing up; the user presses Continue,
  which posts the code like a typed one, through the same Origin check, cookie and throttle (ADR-0805). A crafted link
  never signs anyone in by being opened: the user still signs in and allows on the consent page (ADR-0806).
* **Polling margin.** A device polling every 5 seconds makes 12 requests a minute against the tier's 20. The link,
  login and consent pages from the same address share that bucket (the tier is per address, not per route), so a
  user signing in from the same network as the device leaves a margin of about 8 requests a minute. Each `slow_down`
  halves the device's rate again.

### Positive Consequences

* A device code works once, and a code another client learns is useless to it.
* Every refusal the RFC names is reachable and tested, with no sleep: the store takes the time, and
  `HomeserverRuntime::test_device_grant_clock_advance_ms` moves the clock the handlers read.

### Negative Consequences

* A device that loses the token answer must start again; nothing tells it that the session exists.
* A household signing in from behind one address near the tier's limit can be answered 429 on the pages while a device
  polls.

## Links

* [ADR-0775](0775-auth-metadata-stays-in-the-generic-rate-limit-tier.md), [ADR-0780](0780-oauth-registrations-are-capped-and-idle-clients-are-evicted-least-recently-used-first.md),
  [ADR-0792](0792-an-oauth-grant-is-one-transaction-and-a-replayed-code-ends-only-the-session-it-produced.md),
  [ADR-0805](0805-device-authorisations-and-user-codes-are-held-in-memory-capped-and-guessing-is-throttled-per-address.md),
  [ADR-0806](0806-a-device-sign-in-warns-first-creates-no-account-and-runs-in-one-browser-at-a-time.md)
* RFC 8628 sections 3.1 to 3.5, 5.1 and 6.1
