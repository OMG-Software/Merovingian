# Federation workers relay make_join to main

* Status: accepted
* Date: 2026-10-22

Technical Story: conformance audit 2026-10-17, finding R04

## Context and Problem Statement

`GET /make_join` was answered by a federation worker from its own room snapshot, as
`make_leave` and `make_knock` still are. For a restricted room the template must name a user of
this server who can invite (`join_authorised_via_users_server`), and only after checking that
the joining user meets one of the room's allow conditions (server-server-api.md, "Restricted
rooms", ADR-0185). A condition names another room: the user must be joined to it.

A worker's snapshot is refreshed per room only for the rooms its own shard owns (`room_sync` is
sent to the owning shard). The state of an allowed room in another shard is whatever the worker
loaded at start, or nothing for a room created since, so a worker would refuse users who joined
the allowed room after it started, or authorise users who have since left it.

## Considered Options

* Decide in the worker from its snapshot.
* Send `room_sync` for every room to every shard.
* Relay `make_join` to main, which holds every room, with a new `membership_template_ingest`
  frame.

## Decision Outcome

Chosen option: "relay make_join to main". The worker overrides only the `make_join` case of
`membership_template_provider`; main answers it with its own provider
(`handle_membership_template_ingest_request`) and `make_join` moved to the relay pool
(`federation_endpoint_requires_main_relay`). The frame carries the room ID, the user ID (checked
against the X-Matrix origin by the worker, which main cannot see) and the advertised room
versions. Main treats it as untrusted input (ADR-0071) and checks what it can: it returns no
template for a malformed frame, or for a user ID that is not a valid federated user ID of
another server, since `make_join` is how a remote server's user joins. A template holds only
event IDs of the room's current state, so a compromised worker learns nothing it could not
learn by asking as a remote server. An IPC
timeout or main at its in-flight cap answers the remote with a 5xx, which is retryable.

Fan-out of every room to every shard was rejected: it multiplies snapshot reloads by the shard
count to serve one rarely used check.

### Negative Consequences

* Every `make_join` now costs an IPC round trip to main, also for rooms that are not restricted.

## Links

* Part of [ADR-0185](0185-a-resident-authorises-restricted-joins-only-after-checking-the-allow-conditions.md)
