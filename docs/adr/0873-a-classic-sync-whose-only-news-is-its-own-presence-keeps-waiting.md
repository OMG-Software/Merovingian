# A classic /sync whose only news is the caller's own presence keeps waiting

* Status: accepted
* Date: 2026-11-21

Technical Story: the presence loop of ADR-0871. A classic `/sync` long-poll returned at once whenever the sync stream
moved past its `since`, even when the only new row was the caller's own presence, which `/sync` never sends to its own
user. Each presence change of an account answered every waiting sync of that account with nothing, and each client
synced again at once.

## Context and Problem Statement

The long-poll check of `GET /sync` is "has the sync stream or the timeline moved past `since`?". Sliding sync already
waits past bumps its response would not send (ADR-0863, ADR-0869). Classic `/sync` did not, so a change of the caller's
own presence, including the one the same request's `set_presence` just made, woke it into an empty answer.

## Decision Drivers

* ADR-0863's rule: never wake a poll with a test the response does not share, or it is answered with nothing, again.
* The check runs under `runtime.mutex` on every rerun, so it must cost a constant.

## Considered Options

1. When a `/sync` with a `since` token would answer and its only news is exactly one sync stream position, the
   caller's own presence row (`only_own_presence_since`), answer `needs_wait` with the wait cursor advanced to the
   stream's newest position. The response, when it comes, is built from the request's own `since`, as before.
2. Judge every position after `since` (a walk of each sync surface).
3. Send the caller their own presence, so the answer is not empty.

## Decision Outcome

Chosen option: 1, because it is a constant-time check and covers the case that loops: one device's change waking the
account's other devices, and a request's own `set_presence` waking itself.

* With any other position after `since`, or several, the sync answers as before; the check never delays news.
* A sync with no `since` (an initial sync) is not affected.
* A sync with `full_state=true` never waits, this check or any other: the spec says that with it "the `timeout`
  parameter will be ignored and the query will return immediately". The long-poll gate waited for it before this
  decision.
* The rerun of a woken poll judges again from the same `since`: a new position that is not the caller's presence ends
  the wait.

### Positive Consequences

* A client's own presence change no longer costs it, or its other devices, an empty round trip.

### Negative Consequences

* Two of the caller's own presence changes in a row (at least 5 s apart, ADR-0872) answer the second with nothing, as
  before this decision.
* Option 3 changes what clients are sent; the spec's presence events are for other users.
