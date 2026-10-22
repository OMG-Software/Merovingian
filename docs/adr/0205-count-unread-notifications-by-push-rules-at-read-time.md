# Count unread notifications by the user's push rules at read time, from the start of their join

* Status: accepted
* Date: 2026-10-22

Technical Story: conformance audit 2026-10-17, finding R15 (unread counts ignore push-rule
notify/highlight) and concern 1 (unread counts include pre-join messages)

## Context and Problem Statement

`sync::count_unread_by_thread` backs every unread count: `/sync` `unread_notifications` and
`unread_thread_notifications`, the sliding-sync counts and `by_notification_count` sort, and the
Push Gateway badge. It counted every `m.room.message` and `m.room.encrypted` event as a
notification and every event whose `m.mentions` named the user as a highlight. The spec says
"Notifications are determined by the push rules which apply to an event", and `highlight_count` is
"The number of unread notifications for this room with the highlight flag set". A muted room
still counted, a keyword rule never highlighted, and a highlight was counted even when the rules
did not notify.

It also counted events sent before the user joined. Once the user's own rules decide what counts,
that is a disclosure: a content rule counted over history the user may not see (history
visibility `joined` or `invited`) reveals whether those messages contain a word.

## Considered Options

* Evaluate the user's push rules for each unread event inside the existing count walk
* Count the `notifications` rows that delivery records at ingest
* Record push actions per (user, event) at ingest in a new table, as Synapse does

## Decision Outcome

Chosen option: evaluate in the existing walk. `count_unread_by_thread` asks a
`sync::UnreadEventClassifier` about every unread event. The homeserver's
`PushRuleUnreadClassifier` loads the user's rules once (ADR-0204), computes each room's facts
(power levels, member count and the user's display name, through the same `push_room_facts`
helpers delivery uses) the first time it meets the room, and evaluates `push::evaluate_push_rules`.
An event counts as a notification when the result notifies, and as a highlight when it notifies
with the highlight tweak. Callers build one classifier per request: `/sync`, sliding sync (its
counts and sort), and the badge for each push delivery.

Only events after the start of the user's current join are counted (`current_join_start`): the
earliest `m.room.member` join of theirs with no later leave, ban, invite or knock. A join re-sent
for a profile change does not restart the span. A user who is not joined counts nothing.

Stream order alone is not enough: a backfilled event from before the join is stored, and ordered,
after it. Every counted event therefore also passes `sync::HistoryVisibility::can_see`, the filter
the timeline uses, judged by the state at the event (the classifier's `visible`). `/sync` and
sliding sync lend the request's own filter, so its indexes are built once per request. Only
accepted events count; a rejected or soft-failed event is never served (ADR-0207 records the
same for the badge).

### Positive Consequences

* Every ingest path is covered, because nothing is recorded at ingest.
* A rule change applies at once to what is unread: muting a room clears its count.
* No migration, and the counting path stays the one walk the sync module requires.

### Negative Consequences

* Events are judged against the room's current state (power levels, member count, display name),
  not the state when they arrived.
* Each `/sync` evaluates the rules for every unread event. That costs one evaluation per unread
  event, with the user's rules bounded by ADR-0204, under `runtime.mutex`.
* Events from before the user's join no longer count, even in a room whose history the user can
  read.

## Pros and Cons of the Options

### Count the `notifications` rows

* Good, because evaluation would happen once per event and counting would be cheap.
* Bad, because a user keeps at most `max_notifications_retained_per_user` rows (default 1000),
  oldest first across all rooms, so a busy room would erase a quiet room's unread count.
* Bad, because rows exist only for events that reached the delivery path, and a rule change would
  not apply to events already recorded.

### A per-(user, event) push-actions table

* Good, because it judges each event against the state when it arrived.
* Bad, because it needs a migration and one row per local member per event, plus Synapse-style
  rotation into summaries to keep counting cheap.

## Links

* Related to [ADR-0204](0204-keep-a-users-push-rules-as-their-m-push-rules-account-data.md) (the rules and their bounds)
* Related to [ADR-0170](0170-a-users-own-non-state-event-reads-its-thread.md) (own events read their thread)
