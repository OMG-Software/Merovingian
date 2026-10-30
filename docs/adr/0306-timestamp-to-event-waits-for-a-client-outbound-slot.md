# timestamp_to_event waits for a client-outbound slot within its deadline

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-30

Technical Story: Complement `TestJumpToDateEndpoint/parallel/federation/*`

## Context and Problem Statement

A client request that makes this server call another one takes a slot in the client-outbound budget first
(ADR-0079): half the request pool across all clients, one per client address, and a request with no slot
is refused at once with 429. `GET /_matrix/client/v1/rooms/{roomId}/timestamp_to_event` asks other servers
when its local answer is missing or sits at a gap (ADR-0299). Complement runs five such lookups in parallel
as one user from one address, so all but one were refused, and a lookup with a local answer in hand silently
returned the worse local answer.

## Considered Options

* Wait for a slot within the request's existing deadline
* Raise the per-client cap for this endpoint
* Keep refusing at once

## Decision Outcome

Chosen option: "Wait for a slot within the request's existing deadline" (owner decision 2026-10-30), because
it serves one client's parallel lookups in turn without raising how many outbound calls that client can have
in flight. The request polls for a slot every 25 ms with `runtime.mutex` released, and gives up when the same
`OutboundDeadline` its outbound calls draw from (the 10 s directory deadline) runs out; then it answers as
before (429, or the local answer when it has one). Only this endpoint waits: it requires authentication, and
the unauthenticated proxies ADR-0079 was written for keep the immediate refusal.

### Positive Consequences

* A burst of lookups by one client is answered in turn instead of 429 or a stale local answer.
* The in-flight caps are unchanged: a client still has at most one outbound lookup at a time.

### Negative Consequences

* A waiting request holds a main-pool thread for up to the deadline. One client can hold at most its
  per-client connection share of threads this way (ADR-0077), so the rest of the pool stays available.

## Links

* Refines [ADR-0079](0079-client-triggered-outbound-proxying-runs-under-a-bounded-in-flight-budget.md)
* Related to [ADR-0299](0299-timestamp-to-event-ordering-access-and-asking-other-servers.md)
