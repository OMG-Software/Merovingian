# A worker may have main read a room only under a permit main issued, and only once

* Status: accepted
* Date: 2026-11-12

Technical Story: run-3 audit finding C44,
`F-resource-exhaustion.sqlite-worker.read-lock-held-by-compromised-worker-fails-every-main-write`, step 4 of
[ADR-0733](0733-the-federation-worker-opens-no-database-main-sends-it-what-it-reads.md).

## Context and Problem Statement

The federation worker opens no database; main reads each room for it and sends the rows over IPC (ADR-0733). That
moves the reads into main, but a compromised worker still chooses when to ask. If main read a room whenever a worker
asked for one, the worker could keep main's database busy with reads of any room, as often as it liked, which is the
finding again in another form: on SQLite each read holds a SHARED lock that main's own commits wait for. What may a
worker ask main to read?

## Decision Drivers

* The reads a compromised worker can cause must be bounded by what main does, not by what the worker sends.
* A well-behaved worker must still get every room at start-up and every room main changed.
* No lock may be held across a read: not `runtime.mutex` (the read must not stall main's requests) and not the
  service's own (two shards read in parallel).
* The read transaction must be closed before main sends anything, so a worker that stops reading its channel holds
  nothing in the database.

## Considered Options

* Permits issued by main, consumed once per read
* A rate limit on the worker's reads
* Read whatever the worker asks, as the worker read its own database before

## Decision Outcome

Chosen option: permits. `homeserver::WorkerSnapshotService` answers the three worker store requests and keeps, per IPC
channel (keyed by the channel's identity, dropped with it):

* **The room list**, read once per channel at its page 0, even if that read fails. Each room it names may then be read
  once at generation 0, the start-up fill.
* **Reload permits.** `WorkerPool::notify_room_changed` records (room, generation) as issued on the owning shard's
  channel BEFORE it sends the `room_sync`, so a worker that reloads at once finds it. A request at generation `g` is
  admitted when `admitted < g <= issued`, and sets `admitted = g`; the entry is dropped when `admitted == issued`. So
  a worker that coalesces several notifications reads once, and never reads a room main did not change.
* **Later pages** of a snapshot come from memory, each once and in order. One snapshot is held per channel; a page 0
  drops the one before it, and a held snapshot whose next page is not asked for within 60 s is dropped at the next
  request.

A permit is consumed under the service's mutex before the read starts, so two requests for one permit give one read.
The mutex is released for the read; the service holds no runtime and reads through a store of its own that holds only
where the database is, so `runtime.mutex` is never involved. `read_room` returns only after its read transaction has
ended, and page 0 is sent after that. A key lookup (`server_keys_request`) needs no permit: the keys are public, a key
lookup may run on any worker thread at any time, and main answers from memory (`public_signing_keys_of_server`, at most
256 rows) without reading the database. Every request runs on the snapshot pool (one thread per shard) under the
channel's in-flight cap; a refusal is logged.

### Positive Consequences

* A compromised worker can cause at most one read per room per listing (one listing per channel, so per restart) and
  one per room change main notified. Asking more costs it a refusal and main a parse.
* Main's requests never wait for a worker's read, and a stalled worker holds no database lock.

### Negative Consequences

* A read that fails spends its permit: the worker stays without that room, or with its old copy, until main changes
  the room again (the worker logs it). Retrying would let a worker that makes reads fail ask for more.
* The rows of one held snapshot stay in main's memory until the worker takes them or 60 s pass, one per channel.

## Pros and Cons of the Options

### A rate limit on the worker's reads

* Good, because it needs no state per room.
* Bad, because it still lets the worker choose which rooms are read and when, up to the limit, and a limit low enough
  to protect main's writers would starve a worker filling a large server.

### Read whatever the worker asks

* Good, because it is the simplest.
* Bad, because it is the finding: the worker controls main's database reads.

## Links

* [ADR-0733](0733-the-federation-worker-opens-no-database-main-sends-it-what-it-reads.md) — the design this is part of
* [ADR-0734](0734-a-failed-ipc-write-ends-the-channel.md) — a stalled or failed write of a page ends the channel
* [ADR-0595](0595-bind-worker-key-claim-and-query-relays-to-the-verified-request-by-digest.md) — the relay permits this follows
