# Stored invites are limited per local user and per origin

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, unbounded stored invites per local user

## Context and Problem Statement

`PUT /v2/invite` stored a record, room state included, for every invite a remote server sent, without limit. A server
could fill one user's `/sync` and the main process's memory by inviting them to rooms it invents.

## Decision Drivers

* A cap must be enforced before the write, in the writer, so no caller can skip it.
* A remote server must not be able to starve a user of invites from their own server, or from other servers.
* The spec names the refusal. Server-Server API, `PUT /_matrix/federation/v2/invite`, 403 `M_FORBIDDEN`: "The sender is
  not allowed to send invites to the target user/homeserver".

## Considered Options

* Evict a user's oldest invites past a limit
* Refuse past a limit, counting every invite
* Refuse past a limit, counting only invites from other servers, with a share per origin

## Decision Outcome

Chosen option: "Refuse past a limit, counting only invites from other servers, with a share per origin".

`invite_is_over_store_caps` is asked by `store_membership_projection`, `prepare_store_event_with_state` and `upsert_invite`
before they build a statement, and by the invite handler before it signs anything, which answers 403 `M_FORBIDDEN`.

* A record is charged when the invitee is local and the sender is not (`PersistentStore::local_server_name`). An invite
  from a local user is never charged, and neither is an invite this server's own user sent to someone elsewhere, which is
  recorded here too. While the name is empty, in a store with no runtime, nothing is charged.
* One user holds at most 1024 such invites and 32 MiB of them. One origin may use at most an eighth of either for that
  user, so seven other servers still have room. One origin may hold at most 16384 invites across the server.
* A re-sent invite replaces its record and is not counted again.
* A knock is charged separately: at most 128 per user. A knock past it is refused before the resident is asked.
* The count and entry-size bounds of `invite_room_state` now apply to every room version. Below version 12 the entries are
  still not otherwise validated (ADR-0277).

The limits are fixed policy, members of the store rather than configuration: no deployment has a use for a user
holding more, and each option added is one more thing an operator can set wrongly.

### Rejected: eviction

A remote server could then push a user's real invites out by sending more.

### Rejected: counting every invite

A remote server could fill the same count a local inviter needs.

### Negative Consequences

* A user at the limit gets no further invites from other servers until they accept or reject some.
* `prepare_store_event_with_state` may commit with the lock released, so concurrent writes can overshoot a limit by the
  number in flight.
