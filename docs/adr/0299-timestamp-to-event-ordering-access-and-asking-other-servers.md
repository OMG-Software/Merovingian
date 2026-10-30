# timestamp_to_event: inclusive boundary, a fixed tie order, the read gate, and when other servers are asked

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-30

Technical Story: Complement run 13 (`TestJumpToDateEndpoint`, every subtest answered 404 `M_UNRECOGNIZED`)

## Context and Problem Statement

`GET /_matrix/client/v1/rooms/{roomId}/timestamp_to_event` (CS API, added in v1.6) returns "the event
closest to the given timestamp, in the direction specified by the `dir` parameter", and the federation
endpoint `GET /_matrix/federation/v1/timestamp_to_event/{roomId}` is how "the server does not have all of
the room history" asks other servers. The spec leaves four things open that an implementation must
settle: whether the boundary is inclusive, which event wins when several share a timestamp, who may ask
(the client endpoint lists 200, 404 and 429 only), and when and whom to ask on federation ("the
heuristics ... are left up to the homeserver implementation").

## Decision Outcome

**Boundary and order (owner decision).** The boundary is inclusive: `dir=f` takes events with
`origin_server_ts >= ts`, `dir=b` those with `origin_server_ts <= ts`. Events are ordered by
(`origin_server_ts`, `depth`, `stream_ordering`); `dir=f` picks the smallest qualifying event, `dir=b` the
largest. So with several events in one millisecond, forwards finds the first and backwards the last, which is
what a client that paginates from the result in either direction expects. The same rule serves the
federation endpoint, so a server and the server it asks agree.

**Access (owner decision).** A user for whom `room_read_access_for` says none, in a room that is not
`world_readable`, is answered `403 M_FORBIDDEN`, exactly as `/messages` and `/context` do (the spec lists
no 403 for this endpoint). For a user who may read the room, an event `sync::HistoryVisibility` withholds is
treated as absent and the search goes on to the next event in the direction asked, so the endpoint never
names an event `/event` would refuse to serve. The federation endpoint judges the authenticated requesting
server the way the other federation reads do (ADR-0282): `origin_may_read_room` first (403 otherwise,
unknown rooms included, so a stranger learns nothing), then events none of the origin's users could see
(`ServerEventFilter`) are stepped over. Both stop after `database::max_time_search_examined` (1000) events
offered to the filter; a search cut short answers 404 and, on the client endpoint, asks nobody, because it
does not know that history is missing.

**When other servers are asked (owner decision: the spec's heuristic).** The client endpoint asks other
servers when the local answer is absent, or when the event found sits at a gap: it has a `prev_event` this
server does not hold, by the same notion of "held" as the `/sync` graph-hole rule (`event_is_held`, ADR-0289:
a row that is not an outlier). The candidates are servers other than this one with a joined member in the
room's current memberships, ordered by the lowest stream ordering of a current join of any of their users
(an approximation of the spec's "servers that have been in the room the longest": the join's position in
this server's stream, not the time the server first joined), then by name, at most three
(`max_timestamp_to_event_servers`), asked one at a time. A remote answer is used only if its
`origin_server_ts` lies on the requested side of `ts` and is strictly closer than the local one. The event
is then fetched with `GET /event/{eventId}` through the verified backfill path
(`fetch_remote_event_into_store`: signature, hash and auth checked; stored as an outlier, with the state at it
from the origin's `/state_ids` snapshot when its `prev_events` are not held; never stored unverified), and is
returned only if that succeeds, the user may see it, and its own stored `origin_server_ts` (not the number the
remote server claimed) is still closer than what is held now. Otherwise the client gets the local answer, or
404. The lock is released for each exchange and the state judged again afterwards.

The ask is a client request that calls another server (ADR-0079): it holds a client-outbound slot, draws
every exchange from one `OutboundDeadline` (the 10 s directory deadline) and releases `runtime.mutex` around
each (`RuntimeLockRelease`). With no slot: 429 `M_LIMIT_EXCEEDED` when there is no local answer, the local
answer when there is one (the remote improvement is optional; an answer is not).

## Considered Options

* Inclusive versus exclusive boundary; the owner chose inclusive, which also matches the spec's "closest".
* Order by timestamp alone, leaving ties to the store. Rejected: ties are common (events sent in one
  millisecond) and a client paginating from the result would skip or repeat events.
* Order ties by `stream_ordering` alone. Rejected: `depth` is the room's own order and is the same on every
  server, while stream ordering is this server's arrival order.
* Never ask other servers. Rejected: a server that joined late has no events from before its join, and the
  spec offers the federation endpoint for exactly that.
* Always ask when the room has other servers. Rejected: it costs a round trip and a main-pool thread for
  every request, and the result is wasted when the local history is complete.
* 404 rather than 403 for a user who cannot read the room. Rejected by the owner: `/messages` and `/context`
  answer 403 and a client cannot tell the two cases apart.

## Consequences

* A remote event that is stored for the answer is an outlier: it is not in the room-and-time index (ADR-0300),
  not part of the timeline `/messages` or `/sync` walk, and cannot itself be an answer to a later local lookup;
  asking again asks again (the fetch finds it stored and costs no second download).
* "Longest in the room" is approximated by this server's stream ordering of the join, so a server whose users
  joined long ago but were last re-joined recently is ranked late. The effect is only the order of three asks.
* The ask runs on a request thread for up to the directory deadline; the slot bounds how many do at once.
