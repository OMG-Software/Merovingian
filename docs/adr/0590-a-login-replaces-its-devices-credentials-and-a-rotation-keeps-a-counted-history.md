# A login replaces its device's credentials, and a rotation keeps a counted history of retired refresh tokens

* Status: accepted
* Date: 2026-11-09

Technical Story: Security audit run 4, finding F-08 (part 2 of 2). Part 1 indexed the credential tables (ADR-0325,
ADR-0488); this part bounds the rows.

## Context and Problem Statement

Nothing bounded the credential rows of a device. `POST /login` with a `device_id` the user already held added an access
row (and a refresh row) beside the earlier ones, so a client that logged in again and again left every earlier access
token valid, which the spec forbids (`POST /login` `device_id`: the server invalidates any access token previously
associated with that device). `POST /refresh` revoked the earlier access rows but left them, and kept every retired
refresh row until it expired (ADR-0488: "a revoked, unexpired refresh token is always kept"), which is for ever when
`refresh_token_lifetime_ms` is 0. A login followed by a logout on a fresh device ID left a retired refresh row for a
device that no longer exists. All of it is held in memory and scanned by the retention sweep.

## Considered Options

* A short grace window: delete a retired refresh row some minutes after it was retired.
* Revoke, not delete, the device's earlier refresh rows at login.
* A separate per-user cap on rows.
* Delete at login, keep a counted history on rotation, and drop retired rows of devices that are gone.

## Decision Outcome

The last option.

1. **A login on a device the user already holds replaces that device's credentials.** Every path of `POST /login` ends
   in `complete_login` or `login_local_user_by_id` (password, `m.login.token`, SSO, application service), and both do
   it. In ONE transaction (`store_device_and_access_token` with `replace_device_credentials`) the device's earlier
   access rows and refresh rows are DELETED and the new access row is inserted; memory changes only after the commit,
   and `SessionTable::erase_device` removes the device's sessions. A failed commit is a 500 with no token and nothing
   changed, so there is never a 200 beside a working earlier token. The refresh row of a login that asks for one is
   inserted by `issue_refresh_token_for_session` right after, as before. `POST /refresh` is not a login and keeps its own
   rule (below).
2. **Delete, not revoke.** A revoked refresh row that is presented is treated as reuse (ADR-0074) and revokes every token
   of the device. A stale client still holding the refresh token of the replaced login would therefore end the login that
   just replaced it. An absent row is a plain 401 and harms nothing. The same reason keeps the replacement out of the
   revoke helpers.
3. **A rotation keeps a counted history.** ADR-0074 is unchanged: the presented token stays valid until its successor is
   used, a retry after a lost response works, and presenting a retained retired token ends the device's session. In one
   transaction (`rotate_device_credentials`) the device's earlier access rows are deleted, the new access and refresh rows
   are inserted and the oldest retired refresh rows beyond `max_retired_refresh_tokens_per_device` (32) are deleted;
   `SessionTable::erase_device` then the new session. A retired row is one with `revoked` true. Rows go smallest
   `issued_at_ms` first. An unrevoked row is NEVER named (`CredentialTable::oldest_retired_beyond` only considers revoked
   rows, `rotate_device_credentials` refuses a row that is not retired, and the statement itself carries a bound `revoked = 'true'` condition).
   Cost is the device's rows (`CredentialTable::rows_examined()`).
4. **The sweep drops a retired refresh row of a device that no longer exists** (`collect_unusable_credentials`), from one
   transient set of device keys built per call, not a scan of the devices per token. An unrevoked row is never collected by
   this rule.
5. **No separate per-user cap.** `device_count_limit` (200, F-05, ADR-0582) is enforced by the only two paths that create a
   device (`complete_login`, `login_local_user_by_id`), and a device holds at most one access row after a login or
   rotation, at most two unrevoked and 32 retired refresh rows, and one session. So a user holds at most 200 x (1 + 34)
   credential rows; the number of devices is the per-user bound.

This supersedes the part of ADR-0488 that says a revoked, unexpired refresh token is always kept. ADR-0488's other
decisions (the digest index, deleting sessions and expired or revoked access rows) stand.

### Consequences

* Detection of a reused refresh token reaches the last 32 rotations of a device however slowly the client refreshes, and
  stops there: a token older than that is a plain 401 and the session survives.
* The oldest retired row is chosen by `issued_at_ms`, a millisecond wall clock. Rows issued in one millisecond are ordered
  arbitrarily among themselves, which only matters for which of two equally old tokens is remembered.
* A database that predates `refresh_tokens.issued_at_ms` is not supported before 1.0 (ADR-0224); rows hydrated with 0 are
  the oldest.
* The login's access row and refresh row are written by two commits (`issue_refresh_token_for_session` follows the
  login). If the second fails the client gets an error and no token, the earlier credentials are already replaced, and
  the next login recovers; no earlier token works.

## Pros and Cons of the Options

### A short grace window

* Good, because it is the audit's suggestion and easy to explain.
* Bad, because a client that refreshes less often than the window loses detection altogether, and one that refreshes
  often keeps rows for the whole window.
* Bad, because with `refresh_token_lifetime_ms=0` the rows must still be bounded, which needs a count anyway.

### Revoke, not delete, at login

* Good, because it matches how logout works and reuses the revoke helpers.
* Bad, because a stale client that presents its old refresh token is read as a thief and ends the login that replaced it.

### A per-user cap

* Good, because it bounds a user whatever the paths.
* Bad, because the device cap and the per-device bounds already give a per-user bound, and a user cap evicts a live
  device's credentials, a new way to log a user out.

## Links

* Supersedes the retained-refresh-row part of [ADR-0488](0488-sessions-are-found-through-a-digest-index-and-unusable-credentials-are-deleted.md)
* Refines [ADR-0074](0074-refresh-tokens-retire-on-first-use-of-their-successor.md) (reuse detection is kept, bounded)
* Builds on [ADR-0582](0582-a-user-holds-at-most-200-devices-a-device-name-at-most-256-bytes-and-a-device-list-announcement-is-linear.md)
