# A grown sliding sync timeline_limit skips the long-poll once per request pos

* Status: accepted
* Date: 2026-10-24

Technical Story: Element X showed only the newest message of a conversation written on another
client (0.12.45). Sliding sync sent no `limited` or `prev_batch`, and a raised `timeline_limit`
resent nothing.

## Context and Problem Statement

MSC4186 "Changes to `timeline_limit`" says that when a request raises a room's `timeline_limit`,
the server SHOULD send the room's latest N events even if some were sent before, MUST flag them
with `expanded_timeline`, and "should return rooms that have expanded timelines immediately,
rather than waiting for the next update to the room". Element X raises the limit when a room is
opened, on a request that otherwise long-polls.

The connection state (`SlidingSyncConnectionState`) only advances when a later request
acknowledges a response's `pos`. The `pos` is the live stream watermarks, so a response to a
request in which no stream advanced carries the request's own `pos`. The next request then
cannot be told apart from a retry of the first, and the state is not advanced. So how should the
server answer an expansion at once without letting that repeat answer at once forever?

## Decision Drivers

* An opened room must show its history at once, not after the next event or the timeout.
* A client must never be able to make the server answer at once again and again: that is the
  sync storm 0.10.50 fixed for the encryption connection.
* A lost response must not lose the expansion.

## Considered Options

* Skip the long-poll whenever a request raises a room's limit past the committed state.
* Skip it once per (request pos, room, limit), remembered with the unacknowledged response.
* Never skip it; deliver the expansion with the next update.

## Decision Outcome

Chosen option: "Skip it once per (request pos, room, limit)". `SlidingSyncPendingResponse`
records, in `expansions_answered`, each room whose grown limit its request answered at once.
A request at the same `pos` leaves those rooms out of the check that skips the long-poll. The
room is still built from the committed state, so a request that does go on to answer, after an
event or at the timeout, carries the expansion again. Each room's effective limit is recorded in
`room_timeline_limits` and committed with the rest of the state when the client acknowledges.

### Positive Consequences

* Opening a room answers at once with its latest events (`expanded_timeline`, `limited`,
  `prev_batch`).
* A repeated request at an unchanged `pos` long-polls, so it cannot spin.

### Negative Consequences

* If the response that answered an expansion is lost and nothing advances, the retry waits for
  the next event or the timeout before it carries the expansion again.
* An expansion may resend events the client already holds (a limit lowered and raised again, or
  a room with no recorded limit). MSC4186 allows this ("If the server does not know if it has
  sent down all events it SHOULD send down the latest `N` events"), and clients deduplicate by
  event ID.

## Pros and Cons of the Options

### Skip the long-poll whenever the limit grows past the committed state

* Good, because it is the simplest reading of "return rooms that have expanded timelines
  immediately".
* Bad, because a request whose `pos` no stream advanced keeps finding the expansion
  unacknowledged and answers at once every time: a busy loop for as long as the room is quiet.

### Never skip the long-poll

* Good, because it cannot loop.
* Bad, because an opened room shows no history until something happens in it or the poll times
  out (30 s for Element X), which is the symptom this change fixes.

## Links

* Related: `src/sync/AGENTS.md` "Sliding sync timelines"
