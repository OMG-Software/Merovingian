# An OAuth session row ends with the last credential of its device

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: review finding 2 on `feature/oauth-20-v110`.

## Context and Problem Statement

An `oauth_sessions` row (ADR-0776) was deleted only with its device (`delete_device`) or replaced by a new grant or
login on the device (ADR-0792). Several paths end every credential of a device and keep the device: a password
change with `logout_devices`, a reset or account-page change (`replace_password_without_device`), deactivation,
refresh-token reuse detection, and the expiry of the device's tokens. Each left the row behind. A leftover row keeps
its client from ever being idle, so the client is never evicted at the cap (ADR-0780) or removed by retention
(ADR-0777), and the device still counts as an OAuth device to the UIA gate though nothing of the session is live.
What decides when the row goes?

## Decision Drivers

* The spec forbids deleting a client registration "that has an active session" (Client-Server API, "Client
  registration"); a row whose device holds no live token is not one.
* A row and the tokens it describes must agree after a commit and after a failed commit.
* The sweep keeps the discipline of ADR-0488 and ADR-0489: batches of at most `retention_batch_rows`, at most
  `retention_max_batches` per sweep, one hold of `runtime.mutex` per batch.

## Considered Options

* Delete the row in the transaction that revokes the tokens, and sweep rows whose device holds no live token.
* Keep the rows and teach the client sweep and the cap to judge a client by its sessions' tokens.

## Decision Outcome

Chosen option: delete the row with the tokens, because the row then means what ADR-0776 says it means, and no
reader of it needs to know about tokens.

* `database::revoke_user_credentials` (all of a user's devices, or all but the caller's) and
  `database::revoke_device_tokens` revoke the access and refresh tokens and delete the matching `oauth_sessions` rows
  in one transaction; memory changes only after the commit, and a failed commit changes nothing. Logout's
  `revoke_device_credentials` adds the row's DELETE to its transaction. `deactivate_user_account`,
  `replace_password_without_device`, `change_local_user_password` (with `logout_devices`), `logout_all_local_user`,
  `delete_local_device` and the reuse detection of `refresh_local_session` call them.
* The retention sweep's `sweep_oauth_sessions`, run before the client sweep, deletes the row of a device that holds no
  access or refresh token that is neither revoked nor expired. Each batch is chosen and deleted in one hold of the lock
  and judged again just before the DELETE, so a device granted again between batches keeps its new row. A client whose
  last session ended this way is then idle and may go in the same sweep.

A live access token alone keeps the row, though the finding asked only about refresh tokens: a device holding a
working access token is still an OAuth device, and dropping its row would let it answer UIA with a password.

### Positive Consequences

* A client with no live session is evicted at the cap and removed by retention, as ADR-0777 and ADR-0780 intended.
* A device whose credentials all ended is no longer judged an OAuth device by the UIA gate.

### Negative Consequences

* The sweep walks every session row once per batch under the lock; the session count is bounded by the users'
  device cap.

## Pros and Cons of the Options

### Judge clients by their sessions' tokens

* Bad, because the client sweep, the cap and the UIA gate would each have to read the token tables, and each new
  reader of the row would have to remember to.

## Links

* Amends [ADR-0776](0776-an-oauth-session-is-a-row-keyed-by-user-and-device-and-the-token-tables-do-not-change.md),
  [ADR-0777](0777-an-oauth-client-s-last-use-is-written-at-most-once-a-day.md) and
  [ADR-0780](0780-oauth-registrations-are-capped-and-idle-clients-are-evicted-least-recently-used-first.md)
* Follows the batch discipline of [ADR-0488](0488-sessions-are-found-through-a-digest-index-and-unusable-credentials-are-deleted.md)
