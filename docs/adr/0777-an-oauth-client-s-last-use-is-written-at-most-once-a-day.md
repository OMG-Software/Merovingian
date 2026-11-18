# An OAuth client's last use is written at most once a day

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-16

Technical Story: phase 3 of the [OAuth 2.0 API plan](../todos/oauth-2-0-api.md), the `oauth_clients` retention rule

Amended by [ADR-0808](0808-an-oauth-session-row-ends-with-the-last-credential-of-its-device.md): the retention sweep
first deletes the session rows whose device holds no live token, so a client whose sessions all ended becomes idle and
ages out here.

## Context and Problem Statement

The retention sweep deletes a client registration that has no session and has not been used for 30 days, and
phase 4 caps the number of registrations by evicting the least recently used client without a session. Both need
`last_used_at_ms`. A client is "used" on every authorisation request and every token request, so writing the
timestamp each time would add a database transaction to every refresh of every OAuth device. How precise must the
stored value be, and how are the eligible clients found?

## Decision Drivers

* Retention works in days; an error of up to a day in a 30-day window changes nothing that matters.
* A refresh must not cost a write it does not need.
* The sweep and the cap run under `runtime.mutex`, so finding the eligible clients must cost the clients it returns,
  not every client or every session.

## Considered Options

* Write `last_used_at_ms` only when the stored value is more than 24 hours old (`touch_oauth_client`).
* Write it on every use.
* Keep it in memory only and write it at shutdown.

## Decision Outcome

Chosen option: write at most once a day. `touch_oauth_client` writes nothing when `now` is at or before the stored
value (a clock that stepped back) or within `oauth_client_touch_interval_ms` (24 hours) of it, and otherwise one
`UPDATE` of that row. The in-memory `OAuthTables` keeps the clients that have no session in an ordered set of
(`last_used_at_ms`, `client_id`), maintained by every insert, touch, delete and session change, so
`oauth_clients_without_sessions` walks only the oldest sessionless clients and never reads the session table. A
client with a session is never in that set, and `delete_oauth_clients` refuses one, so neither the sweep nor the cap
can delete it (the spec: "The server MUST NOT delete client registrations that have an active session"). The sweep
asks `oauth_client_has_pending_authorisation` too; it was false until phase 5 kept pending authorisations, and is answered from the stores since [ADR-0782](0782-pending-authorisations-and-authorization-codes-are-in-memory-hashed-bounded-and-never-evicted.md).

### Positive Consequences

* A busy client costs at most one write a day, whatever its number of refreshes.
* The sweep's cost under the lock is the rows it deletes, counted by `OAuthTables::rows_examined()`.

### Negative Consequences

* A client used once, then idle, is deleted up to a day later than an exact clock would say. Accepted.

## Pros and Cons of the Options

### Write on every use

* Good, because the stored value is exact.
* Bad, because every token request becomes a write, under `runtime.mutex`, for a precision retention does not use.

### Memory only, written at shutdown

* Good, because no request writes.
* Bad, because a crash loses every use since start, and a client in use could then be deleted as idle.

## Links

* Related to [ADR-0776](0776-an-oauth-session-is-a-row-keyed-by-user-and-device-and-the-token-tables-do-not-change.md)
* Follows the batch discipline of [ADR-0488](0488-sessions-are-found-through-a-digest-index-and-unusable-credentials-are-deleted.md)
