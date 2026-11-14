# Main serves a room's federation reads while the worker's reload of the room is pending

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-14

Technical Story: Complement `TestEventAuth`, failing since 0.12.90.

## Context and Problem Statement

A federation worker answers a room's federation requests from its snapshot of the room (ADR-0733). When main changes
a room it calls `notify_room_changed`: the room's sync status becomes `pending`, and the worker reloads the room and
reports `ok` or `failed`. `FederationProxy` sent requests to main only after a `failed` reload. In the `pending` window
the worker answered from its old snapshot.

`TestEventAuth` sends a state event, sees it in `/sync`, and asks `GET /event_auth` for it a few milliseconds later. The
worker had not reloaded yet and answered 404 "Event not found" for an event this server had just sent.

How should a request be served while a reload is pending?

## Decision Drivers

* An answer about a room must not be older than what this server has already shown its own clients.
* Main can answer every room read itself: it does when there is no worker, and after a failed reload. Its read
  providers take `runtime.mutex` (ADR-0711).
* Writes (`/send`, the membership endpoints) must keep going through the worker, whose relays to main carry the checks
  of ADR-0071 and ADR-0595.

## Considered Options

* While a reload is `pending`, main serves the room reads that `federation_worker_room_read_may_fallback_to_main` lists
  (GET `state`, `state_ids`, `backfill`, `get_missing_events`, `event_auth`, `timestamp_to_event`), and writes go to the
  worker.
* Hold the request until the worker reports the reload, up to a timeout.
* Leave it as it is, since a remote server retries a 404.

## Decision Outcome

Chosen option: the first. `federation_room_request_served_by_main` makes the decision. It returns true for every
request after a `failed` reload, and for the listed reads while a reload is `pending`. `FederationProxy::handle`
calls it after verifying the request and applying the federation policy, so main receives only verified requests, as
it does after a failed reload. A pending fallback is logged at debug level (`federation_proxy.room_sync_pending_main`).
A failed one stays at warning level.

### Positive Consequences

* A remote server never learns less about a room than this server's own clients already see.
* The predicate that lists main's room reads, written for this purpose and never called, is now used.

### Negative Consequences

* In a busy room every change sets `pending`, so more of the room's reads are answered by main and fewer by the
  sandboxed worker. They are read-only GETs from verified origins, which main already answers when no worker is
  configured.
* `GET /event/{eventId}` names no room, so it is not covered and is still answered from shard 0's snapshot.

## Pros and Cons of the Options

### Hold the request until the reload is reported

* Good, because the worker would still serve every read.
* Bad, because it ties up a request thread for the length of a reload, and a reload that never reports would hold the
  thread until its timeout.

### Leave it as it is

* Bad, because a 404 for an event that exists is a wrong answer, and a server that does not retry keeps it.

## Links

* Builds on [ADR-0733](0733-the-federation-worker-opens-no-database-main-sends-it-what-it-reads.md) and
  [ADR-0735](0735-a-worker-may-have-main-read-a-room-only-under-a-permit-main-issued-and-only-once.md)
* Uses [ADR-0711](0711-the-federation-read-providers-read-main-s-store-under-the-runtime-lock.md)
