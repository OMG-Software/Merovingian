# Main serves every request for a room the federation worker has never loaded

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-14

Technical Story: Complement `TestKnockingInMSC3787Room`, failing on the Linux VM run of 1.0.2 at 7412b050.

## Context and Problem Statement

A federation worker holds the rooms main listed when it started, and loads a room again when main calls
`notify_room_changed` (ADR-0733). A room created after the worker started is in its store only once the first reload of
it has finished. Reloads run on one thread and are coalesced (ADR-0623), so that can take longer than a fast remote
server needs for invite, `make_join` and `send_join`.

ADR-0748 sends a room's reads to main while a reload is pending and keeps its writes on the worker. That is right for a
room the worker holds: a slightly old copy does not change what the worker checks before it relays a write to main.
For a room the worker does not hold at all it is wrong. The worker's `room_version_resolver` finds no create event and
returns nothing, `handle_send_membership` and the `/send` path take room version 12, and the event ID and the
signatures are computed over the redacted event under that version's rules. For an event of an earlier room version
the event ID then differs from the one in the URL, and the worker answers 400 "membership event does not match
endpoint, path or origin". `TestKnockingInMSC3787Room` created a version 10 room and had Complement's server join it
about 250 ms later, and lost that race.

How should a request for a room the worker has never loaded be served?

## Decision Drivers

* A worker must not judge an event under a room version it guessed.
* Main can serve every request for a room: it does when no worker is configured and after a failed reload.
* Requests for a room the worker holds should keep going through the sandboxed worker (ADR-0748).

## Considered Options

* Track per room whether the worker holds it (`RoomSyncStatus::held`). A room main has never notified is held (it was
  in the worker's startup fill, or does not exist). A room's first notification marks it not held, and any successful
  reload marks it held. While it is not held, main serves every request for it, as after a failed reload.
* Have the worker ask main for the room version when it has none.
* Hold the request on the worker until its first reload of the room has finished.

## Decision Outcome

Chosen option: the first. `WorkerPool::notify_room_changed` and `record_room_sync_result` keep the flag (per shard
since ADR-0758), and
`federation_room_request_served_by_main` returns true while it is false. Main already serves a room whose reload failed
in full, so this adds no path main does not have.

Three more ways a worker can lack a room are covered the same way:

* `notify_room_changed` writes the room's status before it checks the worker's channel, so a room first changed while
  the channel is down is not held either.
* The worker's start-up fill leaves out a room main cannot send it, and it reports each one as a `room_sync_result` of
  `failed` at generation 0, which main never assigns. Main records the room as not held
  (`record_room_left_out_of_fill`). It takes the report only for a room in the listing it sent that channel, once
  (`WorkerSnapshotService::consume_fill_omission`), so a worker cannot make main record rooms main never named.
  The flag is kept per shard, and a report marks the room not held only on the shard that sent it
  ([ADR-0758](0758-every-worker-shard-reloads-every-changed-room-and-main-tracks-each-shards-copy.md)).
* A `/send` transaction goes whole to the shard its first PDU picks, so the proxy checks that shard's status of every
  room the transaction names (`federation_request_room_ids`) and serves the whole transaction from main if any of them
  must be. Every shard reloads every changed room (ADR-0758), so the selected shard's copy of a room another shard owns
  is current once its reload lands.

The flag is conservative: main does not record which rooms the startup listing held, so a room that existed at startup
is also not held from its first notification until that reload succeeds. Main serves it for that one reload, once per
room per main process. Recording the listing would avoid that, at the cost of a second copy of the room list.

### Positive Consequences

* A remote server's first join, knock, leave or PDU for a room this server has just created is judged under the room's
  real version.
* Rooms the worker holds keep ADR-0748's split: reads to main while a reload is pending, writes to the worker.

### Negative Consequences

* Main serves a room's requests in full during its first reload, including the first change of each room that existed
  when the worker started.
* A room whose first reload's result never arrives, because the worker restarted, stays with main until its next change
  is loaded. So does a room first changed while the worker's channel was down, even when the restarted worker's fill
  copied it: the fill reports only the rooms it left out.
* A transaction naming one room the worker does not hold is served by main in full, its other rooms included.

## Pros and Cons of the Options

### Have the worker ask main for the room version

* Good, because the worker would still serve the request.
* Bad, because the worker still has no state for the room: every read and every check that needs state would be wrong
  in other ways, and the worker would need a new relay to main.

### Hold the request until the first reload has finished

* Bad, because it ties up a request thread for a reload, which ADR-0748 rejected for the same reason.

## Links

* Refined by [ADR-0758](0758-every-worker-shard-reloads-every-changed-room-and-main-tracks-each-shards-copy.md)
* Refines [ADR-0748](0748-main-serves-a-rooms-federation-reads-while-the-workers-reload-is-pending.md)
* Builds on [ADR-0733](0733-the-federation-worker-opens-no-database-main-sends-it-what-it-reads.md) and
  [ADR-0623](0623-a-workers-room-reloads-are-coalesced-per-room-on-one-thread.md)
