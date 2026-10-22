# Cap a user's global account-data types; room account data stays bounded by membership

* Status: accepted; refined by [ADR-0197](0197-room-account-data-needs-a-membership-and-is-capped-per-room.md) (2026-10-22)
* Date: 2026-10-21

Technical Story: security audit run-1, `sp02.account-data-unbounded-linear-scan`

## Context and Problem Statement

`PUT /_matrix/client/v3/user/{userId}/account_data/{type}` accepts any event type, and each new
type adds a row to `database.persistent_store.account_data`. Requests that read account data
(`/sync`, the sliding-sync `account_data` extension, `GET .../account_data/{type}`) scan those rows
under the global runtime lock. No limit applied, so one authenticated user could add rows without
bound and make every request that reads them, theirs and other users', slower while it held the lock.
The spec sets no limit on how many types a user may store.

## Decision Drivers

* The work done under `runtime.mutex` must not grow with input that one client controls.
* Real clients store a few dozen global types (Element writes about 20).
* Earlier per-user caps refuse rather than evict and are operator-configurable (ADR-0118).

## Considered Options

* Refuse a new global type past a configurable per-user cap; count only global rows
* Count global and room rows against one cap
* Evict the oldest type when the cap is reached
* Index the rows by user so the scans stop growing with other users' data

## Decision Outcome

Chosen option: "refuse a new global type past a configurable per-user cap; count only global rows".
`server.client_api.max_global_account_data_per_user` (default 1000, at most 100000) bounds how many
distinct global types a user holds. A `PUT` for a type the user already holds always succeeds
(it replaces the row). A new type past the cap gets `400 M_TOO_LARGE`, as ADR-0118's caps do.
`database::store_global_account_data_within_cap` counts the user's types and finds the row to
update in the same pass, so the cap adds no second scan under the lock.

Room account data is not counted. Its rows come from `m.tag` (which requires the user to be in the
room) and read markers, so membership already bounds them. Counting them would make a user in many
rooms hit the cap through ordinary tagging.

### Positive Consequences

* One user can no longer grow the rows that every account-data read scans under the lock.
* Clients that update existing types never see the refusal.

### Negative Consequences

* A client storing more than 1000 distinct global types is refused until an operator raises the cap.
* The account-data scans themselves are still linear. They are now bounded, not indexed.

## Pros and Cons of the Options

### Count global and room rows together

* Bad, because room rows are already bounded by membership, and a heavy room user would be refused
  for tagging rooms.

### Evict the oldest type

* Bad, because it silently destroys data the client stored (a push-rules or ignore-list event, for
  example), which the spec gives the client no way to notice.

### Index the rows by user

* Good, because it removes other users' rows from the cost of each scan.
* Bad, because it does not bound one user's own rows, which their own `/sync` still serialises
  under the lock. A cap is needed either way.

## Links

* Follows [ADR-0118](0118-refuse-e2ee-and-filter-uploads-at-per-user-caps.md)
