# An OAuth grant is one transaction, and a replayed code ends only the session it produced

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 6 of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md)

## Context and Problem Statement

A code grant writes a device (when new), an access token, a refresh token, the deletion of the device's earlier
credentials and an `oauth_sessions` row. RFC 6749 section 4.1.2 says a code used twice SHOULD revoke the tokens issued
from it. A device can hold several grants in turn, and a password login can take an OAuth device over. What is written
together, and what does a replay end?

## Decision Drivers

* A failure between writes must not leave a device without its session row, or tokens without a device.
* `oauth_sessions` is keyed by (user, device) (ADR-0776): a later grant on the same device replaces the row.
* A replay may come after a second, legitimate grant on the same device.

## Considered Options

* Write the rows one after another, and on a replay end whatever session the device holds.
* Write them in one transaction (`database::store_oauth_grant`), and on a replay end the device's session only if its
  row is the one that code wrote.

## Decision Outcome

Chosen option: the second.

* `store_oauth_grant` commits the device, the deletes of the device's access, refresh and `oauth_sessions` rows, the
  new access and refresh rows, the new `oauth_sessions` row and the `oauth.session.granted` audit row in one
  transaction (the audit row as ADR-0629 writes it), then updates memory. A failed commit
  leaves none of them and the token endpoint answers 500 `server_error`; the code stays spent.
* Each row's `created_at_ms` comes from `AuthorizationCodeStore::next_session_created_at_ms`, strictly increasing in
  the process. After a grant, `record_issued_session` stores it on the redeemed code. A replay (`redeem` answers
  `replayed`) ends the device's session through `end_device_session_and_announce` only when the device's row names the
  code's client and that `created_at_ms`; otherwise nothing is ended. Either way the replay is `invalid_grant` and is
  logged at warning level (`oauth.code.replayed`).
* A code presented with the wrong client, redirect URI or verifier is spent: it was redeemed before the comparison. A
  malformed verifier is refused before the code is redeemed (`invalid_request`).
* `store_device_and_access_token` with replacement (every password login on a held device) also deletes the device's
  `oauth_sessions` row in its transaction: after `POST /login` on an OAuth device, the device is a legacy session
  (ADR-0793).

### Negative Consequences

* The replay record lives in memory with the code (60 s, ADR-0782). A replay after a restart, or after the code
  expired, is an unknown code and ends nothing.
