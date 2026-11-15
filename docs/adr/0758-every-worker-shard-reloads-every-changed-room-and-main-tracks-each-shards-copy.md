# Every worker shard reloads every changed room, and main tracks each shard's copy

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-14

Technical Story: CodeRabbit review of PR #592 on the ADR-0756 fix; owner decision "Fix properly in this PR".

## Context and Problem Statement

With more than one worker shard, a room's requests go to the shard its room ID hashes to (FNV-1a), and until now only
that shard was told when the room changed. But a `/send` transaction goes whole to the shard its first PDU picks
(ADR-0131), and may carry PDUs for rooms other shards own. That shard's copy of such a room was its start-up snapshot,
or nothing for a room created since, whatever main recorded about the owner's copy. So the worker could judge a PDU
against old state, or under a guessed room version (ADR-0756).

The first fix served such a transaction from main whenever its rooms spanned shards. That breaks ADR-0131's sandbox
boundary: a remote server chooses which rooms its transaction names, so any remote could steer its transactions into
the main process by naming rooms of two shards.

How should a worker answer for a room another shard owns?

## Decision Drivers

* A remote server must not be able to choose whether its request is handled by main or by the sandboxed worker
  (ADR-0131).
* The worker that answers a request must hold a current copy of every room the request names, or main must answer it.
* One transaction ID is answered once, by one process.

## Considered Options

* Tell every shard of every room change, and keep each room's sync status per shard. A request is judged on the copy of
  the shard it is sent to.
* Serve a transaction from main when its rooms belong to more than one shard.
* Split a transaction by room and send each part to the room's owning shard.

## Decision Outcome

Chosen option: the first. `WorkerPool::notify_room_changed` assigns one generation per change, marks the room
`pending` on every shard and sends `room_sync` to every healthy shard, with a reload permit on each channel (ADR-0735).
Each `room_sync_result` is recorded against the shard that sent it, and so is a start-up fill omission (ADR-0756).
`FederationProxy::handle` picks the shard first (`shard_for` of the request's routing room, shard 0 for none) and checks
`room_sync_status(shard, room)` for every room the request names; ADR-0748 and ADR-0756 then apply to that copy. A
result can only be recorded for a generation main issued, or for a room main listed to that channel, so a worker cannot
grow main's maps.

`GET /hierarchy` stays with main (ADR-0712): the proxy judges only the room in a request's path, and a hierarchy reads
child rooms whose reloads may be pending or failed on the selected shard.

### Positive Consequences

* No request reaches main because of which rooms a remote server named; main answers only for a copy the selected
  worker lacks or has not yet updated.
* A transaction naming rooms of several shards is handled by one worker, with current copies of all of them.

### Negative Consequences

* Every room change makes every shard reload the room: with `N` shards, `N` snapshot reads in main per change. The
  default (`shards = 1`) is unchanged. Reloads stay coalesced per room on each worker (ADR-0623).
* Main keeps one status entry per shard for each room it has notified.

## Pros and Cons of the Options

### Serve a cross-shard transaction from main

* Good, because it is a small change.
* Bad, because a remote server decides, by the rooms it names, that its transaction is parsed and judged by main
  instead of the sandboxed worker, which is what ADR-0131 forbids.

### Split a transaction by room across shards

* Bad, because one transaction ID would be answered piecemeal by several workers, and the per-PDU results would have
  to be merged in main.

## Links

* Refines [ADR-0756](0756-main-serves-every-request-for-a-room-the-worker-has-never-loaded.md)
* Keeps [ADR-0131](0131-keep-malformed-first-pdu-transactions-inside-worker-shard-zero.md) and
  [ADR-0712](0712-a-space-hierarchy-request-is-answered-by-main-not-by-a-worker-snapshot.md)
* Builds on [ADR-0735](0735-a-worker-may-have-main-read-a-room-only-under-a-permit-main-issued-and-only-once.md) and
  [ADR-0748](0748-main-serves-a-rooms-federation-reads-while-the-workers-reload-is-pending.md)
