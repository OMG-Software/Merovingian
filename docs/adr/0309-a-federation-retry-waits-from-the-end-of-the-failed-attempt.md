# A federation retry waits from the end of the failed attempt

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-30

Technical Story: Complement `TestToDeviceMessagesOverFederation/stopped_server`

## Context and Problem Statement

The outbound dispatch worker retries a failed transaction after a backoff that doubles from 2 s (4, 8, 16,
32 s ...). It counted the backoff from when the attempt started. A connection to a stopped server times out
after about ten seconds, longer than the early backoffs, so each failed transaction was due again the moment
it failed: three attempts in thirty seconds used up the doubling, and the next one came half a minute after
the peer was back. The shutdown drain took every due transaction, including one it had just failed, so a
worker whose peer was down kept the process alive until it was killed. The idle loop woke whenever the queue
was not empty, so it spun for the whole of every backoff. The spec says nothing about retry timing.

## Considered Options

* Count the backoff from the end of the attempt; the drain takes only what was due when it began; the idle
  wait wakes only for a due transaction
* Keep counting from the start and cap the backoff lower
* Reset a destination's backoff when it sends this server a request

## Decision Outcome

Chosen option: "Count the backoff from the end of the attempt", because it makes the backoff mean what it
says however long an attempt takes, and leaves the curve itself alone. The drain finishes work that was due
when shutdown was requested and keeps a transaction that fails during it for replay at the next start, so
shutdown ends after at most one attempt per due transaction. A lower cap would only hide the miscount, and a
peer that is back need not send anything first.

### Positive Consequences

* A peer that comes back is tried again within its current backoff, not several backoffs later.
* Shutdown is bounded by the attempts already due, and an idle worker does not spin.

### Negative Consequences

* A transaction due when shutdown is requested still gets its attempt, which can take up to the outbound
  timeout before the process exits.

## Links

* Related to [ADR-0177](0177-each-outbound-destination-holds-a-bounded-share-of-the-dispatch-queue.md)
