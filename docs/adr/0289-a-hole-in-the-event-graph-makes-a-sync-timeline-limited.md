# A hole in the event graph makes a /sync timeline limited

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-30

Technical Story: Complement `TestSyncTimelineGap/full` and `/incremental` (matrix-org/synapse#16463):
a remote server's burst of events reached us with 39 of its predecessors missing, and `/sync`
returned the 13 events we held with `"limited":false`.

## Context and Problem Statement

The `limited` field of a joined room's `timeline` reads "True if the number of events returned was
limited by the `limit` on the filter" (client-server-api.md, `GET /sync`). The Syncing section
describes it as the signal for a gap: "The client may therefore end up with 'gaps' in its knowledge
of the message timeline. The client can fill these gaps using the `/rooms/{roomId}/messages`
API." Taken literally the field text covers only a window larger than the filter limit. A server
that receives an event over federation whose `prev_events` it never received (it fetches some with
`get_missing_events`, but only a bounded number) has a gap in its own event graph: the events before
the hole are not in the store, `/messages` can only reach them by backfilling, and a client that
has never been told the timeline is discontinuous keeps appending the new events to the last ones
it saw. The spec does not say what `limited` must be in that case.

## Decision Drivers

* A client must be told when the events it is given are not contiguous with what it already holds.
* `/sync` runs under `runtime.mutex`; the work must be bounded by the response, not by the store.
* An over-report of `limited` costs a client one `/messages` call; an under-report loses a gap.

## Considered Options

* Read `limited` literally: only a window larger than the filter limit is limited.
* A hole in the room's event graph also makes the timeline limited, and the timeline starts at the
  event after the hole.
* Mark the timeline limited but keep the events before the hole in the same batch.

## Decision Outcome

Chosen option: a hole makes the timeline limited, and the timeline starts at the event after it.

The classic `/sync` joined-room builder takes the window it would return (the newest
`timeline_cap` events that pass the filters) and looks at each event in it, newest first. An event
has a hole before it when any ID in its `prev_events` is not **held**. The window then starts at
the newest such event (that event is kept: the hole lies before it), `limited` is true, and
`prev_batch` is the stream ordering of the window's first event, so `/messages?dir=b` returns the
events before it, backfilling over the hole. Alice's pre-gap message in `TestSyncTimelineGap` is
left to `/messages` for the same reason: a batch that held it and the post-gap events would be one
timeline with a discontinuity in the middle.

An event is **held** when `store.events` has a row for its ID whose status is not `outlier`.
Rejected and soft-failed events are held: they are in the graph the server walked, they are only
withheld from clients. An outlier (ADR-0064: a `send_join` state or auth-chain event, an invite or
leave stub, an unverified backfill) is stored for auth-chain lookups but is "not reachable by
walking `prev_events` from anything we hold", so a `prev_event` that is only an outlier is a hole
too: the stretch between it and the events we hold was never received. An outlier is never itself
the event the check starts from, because it is not part of the live graph and its predecessors are
missing by construction. Because the first event a server accepts after a remote join has the
remote room's earlier events as `prev_events`, the first sync after joining a federated room is
limited too, which is accurate: history before the join exists and is reachable through
`prev_batch`.

Cost: the check reads only the events of the returned window (at most the filter limit, itself
capped by `max_sync_events_per_room`) and does one `EventTable::contains`, an indexed hash lookup,
per `prev_event`. It never scans the store. The existing per-room scan that builds the window is
unchanged. A window already cut by the filter limit needs no look at the events it dropped.

A limited incremental response carries the state at the start of the timeline, because the spec
says the limited response includes a state delta over the gap and the lazy-loading text requires
the membership events in it. The server sends the whole state at the timeline start, a superset of
the delta, as it already does for an initial sync.

Sliding sync (MSC4186) has its own builder, `build_room_response`, and its own `limited` rule
("fewer events than it could"); it is not changed here.

### Negative Consequences

* A limited timeline for a window smaller than the filter limit is a reading of the Syncing prose,
  not of the `limited` field text. A reader who takes the field text literally will want to undo it;
  `tests/unit/test_sync_dag_gap.cpp` pins the behaviour.
* The state sent for a limited incremental sync is not a minimal delta.
* A room with a persistently unfillable hole (an event whose predecessors the remote server will not
  serve) reports `limited` for the window that contains it, once per sync that window appears in.

## Pros and Cons of the Options

### Read `limited` literally

* Good, because it is exactly the field text.
* Bad, because the client is never told about a gap this server cannot fill from its own store.

### A hole also makes the timeline limited (chosen)

* Good, because it matches the Syncing prose: the timeline is discontinuous and the client fills it
  through `/messages`.
* Good, because the cost is proportional to the response.
* Bad, because it extends the field text.

### Limited, with the events before the hole in the batch

* Bad, because the batch then holds events on both sides of the hole in one timeline, which a client
  cannot tell from a contiguous one.

## Links

* Related to [ADR-0064](0064-spec-conformant-pdu-ingestion-with-delta-state-groups.md) (outlier status)
