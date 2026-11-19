# Sticky events reach clients once per sync position, and in full on joining or entering scope

* Status: accepted
* Date: 2026-11-19

## Context and Problem Statement

MSC4354 adds a per-room `sticky` section to classic `/sync` for unexpired sticky events that fall outside the
timeline, and MSC4480 adds a sliding-sync extension for them. The `/sync` section is stream-like: an event is delivered
once, and every unexpired sticky event is delivered when the user joins. `StreamToken` has no spare component, and
classic `/sync` keeps no per-client state. How does each sync surface decide which sticky events to send?

## Decision Outcome

### Classic `/sync`

Sticky events are PDUs, so they already have an event ordering. The section needs no new stream and no change to the
token format, which would invalidate every client's saved `next_batch`.

For each room in `rooms.join`, the candidates are the room's unexpired sticky rows
([ADR-0854](0854-a-sticky-event-is-a-row-beside-the-event-expiring-an-hour-at-most-after-it-was-first-seen.md)) whose
event ordering is at or before the response's upper bound and whose sender the user does not ignore. Of those:

* **Initial sync, `full_state=true`, or a room the user joined after `since`:** every candidate.
* **Otherwise:** the candidates whose event ordering is after `since`.

An event in this response's `timeline.events` is left out of the section. The timeline filter is applied first, so a
sticky event the filter removed from the timeline is in the section. The `state` and `timeline` filters do not apply
to the section. Events are ordered oldest first. History visibility is not applied, as MSC4354 says (on every endpoint,
[ADR-0858](0858-unexpired-sticky-events-skip-history-visibility-reach-every-client-whole-and-follow-msc4508-scope.md)), and there is no section for invited, knocked or left rooms.

The section has no cursor: classic `/sync` has none, so events left out would be skipped by `next_batch`. It carries
every event a response chooses, and the room cap
([ADR-0857](0857-a-room-holds-a-bounded-number-of-sticky-events-shared-fairly-between-servers.md)) bounds what a room
holds ([ADR-0858](0858-unexpired-sticky-events-skip-history-visibility-reach-every-client-whole-and-follow-msc4508-scope.md)).

A room whose only news is sticky events is not suppressed as empty. With `lazy_load_members`, a sticky event's sender
gets their membership event as a timeline sender does. A new sticky event wakes a long poll as any new event does; an
expiry wakes nothing.

### Sliding sync

The extension takes `enabled`, `limit` (default 100, at least 1; a larger value is lowered to 100) and the `lists` and
`rooms` scope of MSC4508 ([ADR-0858](0858-unexpired-sticky-events-skip-history-visibility-reach-every-client-whole-and-follow-msc4508-scope.md)). The connection state remembers, per room, the sticky event IDs it has
delivered. For each room in scope that the user is joined to, the response holds the unexpired, unignored sticky events
not already delivered on this connection and not in this response's timeline for that room, oldest first, at most
`limit`. Delivering an event in the timeline also marks it delivered. Expired IDs are dropped from the remembered set.

So:

* a new connection, including one after `M_UNKNOWN_POS`, or enabling the extension on an existing connection, gets
  every unexpired sticky event;
* a room re-entering scope gets the events it has not had yet;
* events left over by `limit` come in the next response, and a backlog of them answers a long poll at once;
* a repeated `pos` gets the same response again, as the existing connection-state model already guarantees.

## Consequences

* Classic `/sync` carries every unexpired sticky event a response chooses, at most the room cap (ADR-0857, ADR-0858).
* The unstable and stable `/sync` keys carry the same array
  ([ADR-0853](0853-sticky-events-are-served-on-the-unstable-names-released-clients-use-and-the-stable-names.md)).

## Links

* Related: [ADR-0853](0853-sticky-events-are-served-on-the-unstable-names-released-clients-use-and-the-stable-names.md)
* Related: [ADR-0854](0854-a-sticky-event-is-a-row-beside-the-event-expiring-an-hour-at-most-after-it-was-first-seen.md)
* Amended by [ADR-0857](0857-a-room-holds-a-bounded-number-of-sticky-events-shared-fairly-between-servers.md)
* Amended by [ADR-0858](0858-unexpired-sticky-events-skip-history-visibility-reach-every-client-whole-and-follow-msc4508-scope.md)
