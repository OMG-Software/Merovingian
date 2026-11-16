# A recovery asks the origin for a listed state event at most once

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-15

Technical Story: production log of pong.ping.me.uk at 1.0.2, 2026-11-15: about 95% of a day's warnings came from
three retained PDUs in one room.

## Context and Problem Statement

`backfill_missing_pdu_references` recovers the history a PDU lacks. When `/get_missing_events` and `/event` leave a
gap, it asks `GET /state_ids` at up to `backfill.max_outbound_calls` gap events (`state_snapshot_targets`), and each
snapshot fetches every state event it lists with `GET /event` before it stores any. One listed event the origin will
not supply ends that snapshot.

In the log, matrix.kahlilia.org answered every `/state_ids` request, and every answer listed the same state event,
which it then refused with 403 on `/event`, most likely because this server had not joined when the event was sent.
Each recovery therefore asked for that one event 15 times, once per snapshot target, and logged two warnings each
time. The deferred PDU retry (30 s doubling to 1 h, 10 attempts) repeated the whole recovery.

Should a recovery ask the origin again for a listed state event it has already failed to supply?

## Decision Drivers

* The origin decides what it serves. A refusal, a 404 or an unusable answer for one event does not change within
  one recovery, which is bounded by `backfill.timeout_seconds` (45 s by default).
* Every snapshot needs every state event it lists, so a snapshot listing one that was not supplied cannot be
  completed, whatever else it lists.
* The repeat is per snapshot target: the per-reference stage asks for each missing reference once, and each snapshot
  asks for its own target once, so neither multiplies with the number of gaps.
* The history may become available later: the origin may fetch it, or this server may gain the right to see it.
  The deferred retry exists for that.

## Considered Options

* Remember, for the rest of one recovery, each state event a `/state_ids` snapshot listed and the origin did not
  supply; a later snapshot that lists one ends at once without asking.
* Remember every event ID any `GET /event` of the recovery did not supply, and send no further request for it.
* Stop trying further snapshot targets after the first snapshot fails.
* Remember unsupplied events across recoveries, for example in the retained PDU's row.

## Decision Outcome

Chosen option: the first. `BackfillBudget::unsupplied_events` holds the IDs. `backfill_state_ids_snapshot` records a
listed state event whenever its fetch brought back no usable PDU (refused, missing, another event, or no answer),
and ends a later snapshot that lists a recorded ID, neither held nor stored since, before it fetches any of its listed
events, logging at DEBUG, since the failure itself was logged at WARNING when it happened. The check comes first
because phase 1 stores nothing until every event is in hand: a snapshot that fetched the events listed before the
refused one would fetch them again only to discard them. `fetch_event_by_id` and `fetch_snapshot_event_by_id` neither record nor consult
the set. The set belongs to one `BackfillBudget`, so it never outlives the recovery, and the next deferred retry asks
again.

`/state_ids` itself is still asked at every target: each target is a different question, and its answer may list
only events the origin does serve.

### Positive Consequences

* A recovery whose snapshots all list one refused event sends one `/event` request for it, not one per target, and
  logs its failure once. In the observed case that is 15 requests and 30 warnings down to 1 and 2.
* The calls saved are left in the recovery's budget for targets that can still succeed.
* A snapshot's target is still fetched after its state is known even when the per-reference stage could not get it
  (ADR-0069, ADR-0070).

### Negative Consequences

* A listed state event whose fetch failed for a transient reason, such as a timeout, is not retried within the same
  recovery. The deferred retry still asks again, as it did before.

## Pros and Cons of the Options

### Remember every unsupplied event

* Good, because it would also save the target fetch after a per-reference fetch of the same event failed.
* Bad, because that saves at most one request per gap event, and it takes away the second ask that the snapshot path
  relies on: an event the per-reference stage could not get is fetched again as the snapshot's target once its
  state is known. The ADR-0069 and ADR-0070 scenarios fail with it.

### Stop after the first failed snapshot

* Good, because it saves the `/state_ids` requests too.
* Bad, because the other targets are different gaps, and their snapshots may list only events the origin serves.

### Remember across recoveries

* Good, because the retries would also skip the request.
* Bad, because it would refuse history that has become available since, and it needs persistent state that the
  deferred retry's own limits already bound.

## Links

* Refines [ADR-0069](0069-spec-conformant-state-ids-fallback-via-event-auth.md) and the A8 recovery rules in
  `src/homeserver/AGENTS.md`
