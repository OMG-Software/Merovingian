# `/messages` and `/context` do not track redundant members

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

`GET /rooms/{roomId}/messages` already returns only the chunk senders' members under `lazy_load_members`, and
`GET /rooms/{roomId}/context/{eventId}` now does too. Both could, like `/sync`, skip members already sent.

## Considered Options

* Track what was sent to a client across pagination calls
* Stay stateless: always send the senders' members, redundancy allowed (spec: "valid for the server to send redundant
  membership events")

## Decision Outcome

Chosen option: stateless. Pagination has no acknowledgement token: a `from` token says where to read, not what the client
received, so a lost page cannot be told from a received one and ADR-0450's rule cannot be applied. `/context` is a single
request with no token at all. For `/context` the filter's `types` and `senders` select the chunk's events, so they do not
remove the members (as on `/messages`), and the helper `apply_lazy_member_loading` is shared. `state` holds only the
members of the senders of `events_before`, `event` and `events_after`, as of the same point in time `/context` used before
(the last event returned).

### Negative Consequences

* Each page repeats the members of its senders.
