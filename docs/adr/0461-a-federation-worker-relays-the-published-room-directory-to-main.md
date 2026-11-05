# A federation worker relays the published room directory to main

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

Most federation read endpoints answer from the worker's own room-scoped snapshot, on the fast local thread pool. The published
directory looks like one of them, since it only reads.

## Considered Options

* Answer in the worker from its snapshot
* Relay to main over IPC, as `query/directory` does

## Decision Outcome

Chosen option: relay to main (`public_rooms_ingest`), because the worker cannot give a correct answer:

* The route names no room, so it always lands on shard 0, whichever rooms are listed, and shard 0 holds only part of the
  directory when `shards` is above 1.
* A snapshot is refreshed by `room_sync` for the routes that name a room, so a room published after the worker started would
  stay missing.
* `third_party_instance_id` and `include_all_networks` read appservice registrations, which a worker never loads (ADR-0296).

Main treats the frame as untrusted input (ADR-0071). The frame carries the request as a POST body
(`serialize_public_rooms_request`) and main reads it with `parse_public_rooms_body`, so a compromised worker gets no more than
a remote server's request could. A frame main refuses is answered with no listing, and the worker answers 503 `M_UNAVAILABLE`,
never an empty directory: an empty one would tell a remote server this server publishes nothing.

X-Matrix authentication and the per-origin cap have already run on the way in by then, as for every relayed query. The route is on the relay pool, because a thread spends the call blocked on main.

### Negative Consequences

* The answer crosses IPC, so a page has to fit `kIpcMaxFrameBytes` (ADR-0460 caps it at 8 MiB).
