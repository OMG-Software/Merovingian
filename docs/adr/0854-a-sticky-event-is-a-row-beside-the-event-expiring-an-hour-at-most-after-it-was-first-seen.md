# A sticky event is a row beside the event, expiring an hour at most after it was first seen

* Status: accepted
* Date: 2026-11-19

## Context and Problem Statement

MSC4354 defines a sticky event's lifetime as starting at `min(received_ts, origin_server_ts)` and lasting
`min(duration_ms, 3600000)` milliseconds, where `received_ts` is when this server first received the event. The
`events` table stores no received time, and the stored event JSON does not change after it is persisted. Where does
the server keep what it needs to deliver sticky events, and what bounds that?

## Decision Outcome

**A `sticky_events` table (migration 005), with an in-memory mirror like `delayed_events`.** One row per sticky event
this server accepted: `event_id` (primary key), `room_id`, `sender`, `received_at_ms` and `expires_at_ms`, all `TEXT`
like the other tables. The row is written in the same step that persists the event, so the clock reading is taken once:

* A locally composed event: `received_at_ms` is the event clock's reading when the server composed it, not the
  stamped `origin_server_ts`. They differ only when an application service sets `?ts=`, and taking the clock means a
  chosen timestamp cannot extend the event's life.
* An event from federation: `received_at_ms` is the wall-clock time the main process accepted it, never a time the
  sending server supplied.
* `expires_at_ms = min(received_at_ms, origin_server_ts) + min(duration_ms, 3600000)`. A remote server cannot extend
  an event's life by stamping it in the future. An event whose expiry is already past when it arrives gets no row.

The expiry is computed by one pure function in `events/` that also decides whether a PDU is sticky (the reading rules of
[ADR-0853](0853-sticky-events-are-served-on-the-unstable-names-released-clients-use-and-the-stable-names.md)), so the
send path, federation ingest and the tests agree.

**Only accepted, timeline events get a row.** A rejected event, a soft-failed event and an outlier get none. MSC4354
asks for a soft-failed sticky event to be re-evaluated when the room's state changes; this server does not, so such an
event is never sticky here. That is a known gap.

**A row goes away when the event stops being sticky.** It is deleted when:

* it has expired: a `sticky-events` periodic job deletes expired rows, and every reader ignores a row whose
  `expires_at_ms` has passed, whether or not the job has run;
* the event is redacted: redaction removes the sticky fields, so the row is deleted when the redaction is accepted;
* the sender's account is deactivated, for a local sender, as delayed events are
  ([ADR-0824](0824-a-delayed-event-is-a-stored-row-kept-after-it-is-finalised-bounded-per-user-and-deleted-with-the-account.md)).

**At most `server.sticky_events.max_per_sender` unexpired sticky events per sender (default 60), across all rooms.**
Recording one more expires the sender's oldest row (earliest `expires_at_ms`) instead of refusing the new event, as
MSC4354 suggests: the newest call membership is the one that matters. This applies to local and remote senders alike, so
a remote server cannot grow the table without bound through one user. A local send is never refused for this cap.

**Delayed sticky events.** A delayed event scheduled with a sticky duration stores it in a second table of the same
migration, `delayed_event_sticky_durations` (`delay_id` primary key, `sticky_duration_ms`), written in the transaction
that stores the delayed event. The in-memory `DelayedEventTable` row carries it as an optional field. The migration
framework builds each step from `Schema.cpp`'s table arrays and has no add-column step, and `delayed_events` is already
released, so its definition is not changed. The side row is deleted in the transaction that finalises, deletes or
prunes its delayed event; a side row whose delayed event is missing or finalised is ignored at load and deleted by the
`sticky-events` job. When the event is sent it goes through the ordinary sticky send path, so its lifetime starts
when it is sent, not when it was scheduled.

**Configuration.** `server.sticky_events.enabled` (default `true`, like delayed events,
[ADR-0826](0826-delayed-events-are-on-by-default-with-a-maximum-delay-per-user-caps-and-per-user-rate-limits.md))
and `server.sticky_events.max_per_sender` (1 to 1000). Both are read at start-up. Turning the feature off stops new
sticky sends and stops serving the `/sync` sections and the extension; it does not change events already stored.

## Consequences

* The federation worker never reads `sticky_events`; it is a main-process table.
* Sticky events persisted before this version have no row and are not sticky, which matches Synapse's behaviour for
  events persisted before its feature flag was turned on.

## Links

* Related: [ADR-0853](0853-sticky-events-are-served-on-the-unstable-names-released-clients-use-and-the-stable-names.md)
* Related: [ADR-0824](0824-a-delayed-event-is-a-stored-row-kept-after-it-is-finalised-bounded-per-user-and-deleted-with-the-account.md)
