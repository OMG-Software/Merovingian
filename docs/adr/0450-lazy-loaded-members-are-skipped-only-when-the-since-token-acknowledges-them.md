# Lazy-loaded members are skipped only when the `since` token acknowledges them

* Status: accepted
* Date: 2026-11-04

## Context and Problem Statement

With `state.lazy_load_members` on `GET /sync`, the spec lets the server skip a member event the client was already sent
("the server MAY assume that clients will remember membership events they have already been sent"), and says "it is
valid for the server to send redundant membership events". Skipping needs a record of what was sent. A response can be
lost after the server built it, and the server cannot tell. A record that says "sent" then loses a member for good.

## Considered Options

* A set of (user, device, room, member) the server has sent
* An acknowledgement-based record: an entry holds the member's event ID and the `next_batch` of the response that carried
  it, and counts only once a request has presented exactly that token as its `since`
* The same record, but counting as soon as a later request's `since` is at or past that token on all three components
  (rejected, see below)
* No record: always send every timeline sender's member (valid, wasteful)

## Decision Outcome

Chosen option: the acknowledgement-based `sync::LazyMemberTracker`.

The rejected sent set breaks on this sequence. Response R1 (`since` T0) carries bob's member event and is lost. The
client retries with T0. R2 is `limited`, so bob's earlier events fall into the gap and bob is no timeline sender: R2 does
not carry bob, and the sent set still says he was sent. Bob next speaks in a response with `since` T2; the set says
"sent", so his member is skipped and the client has never seen it. The tracker prevents this by these rules:

* Every entry is recorded *pending*, also when a member is sent again. A pending entry is never redundant.
* At the start of a request with a `since`, a pending entry whose token equals `since` on all three components becomes
  *settled*, and any other pending entry is deleted. A client echoes `next_batch` verbatim and it is opaque, so only an
  exact match proves it received that response.
* A settled entry is deleted if `since` does not cover its token (a retry of an older token proves the client never
  received a response it was sent). A request with no `since` deletes everything under its key.
* A member is redundant only if its entry is settled, its stored event ID equals the current member event ID and the
  request's `since` covers the stored token on `event_ordering`, `membership_ordering` and `sync_stream_id`.
* A room the user has just joined (or rejoined) in this response's window does not consult the tracker, though what it
  sends is still recorded: a client may discard a room on leave, so after a rejoin it may no longer hold a member the
  tracker says it does.

A left room's limited timeline owes the member changes of the gap, so it reads whole state, and that read stops at the
event that ended the user's join (`RoomReadAccess::boundary_ordering`). A user banned after leaving has the ban in the
timeline, and the state before the ban names people who joined after they left, so a timeline that starts past the
boundary is answered from the state at the boundary. If the state at the timeline's start cannot be rebuilt, the answer
is the room's state as of the same limit, never an empty list and never the sender-only `build_lazy_sender_members`,
which would lose the gap's changes. The joined-room fallback's `sync_position` must not be copied here: it would read
past the leave.

The same limit holds for an unlimited timeline that starts past the boundary, which only the later ban or a
world-readable room can produce: the senders' members come from the state at the boundary. A sender who joined after
the user left therefore has no member event in `state`, and a client shows their Matrix ID. That omission was chosen
over sending the member event the lazy-loading rule would ask for: it discloses less, and the event's `sender` still
says who acted. `LazyRoomSelector::Plan::newest_readable` enforces the limit for every read, because
`member_event_at_timeline_start` falls back to the current member event when a state group cannot be read.

The first version accepted a `since` "at or past" the stored token. That fails when a client aborts a long-poll and
retries the same `since` while the first request still runs. Request B begins at S0. Request A (also S0) records Bob at
R1 and answers a dead connection. B answers at R2 >= R1 with Bob pushed out of its timeline into the gap by `limit`, so B
did not send him. The client presents R2, which covers R1, so Bob counted as held though the client never received him,
and his member was omitted the next time he spoke. Under the exact rule R2 is not R1, so the entry is deleted.

Keys are (user, device, the request's `filter` value verbatim, room); two filter streams of one device, and two devices of
one user, are tracked apart. A request with no device ID, or a `filter` over 2048 bytes (untracked, chosen over
truncating or hashing it), neither consults nor records. Members are recorded only when sent in `state`, only after the
body is built, and only when `next_batch` differs from `since` (a client cannot acknowledge a response whose token it
already holds). `include_redundant_members` and `full_state=true` do not consult the tracker; lazy-loading off does
nothing with it.

Bounds, because the input is client-controlled: `Limits` caps streams (1024), rooms per stream (64), members per room
(64) and members in all (131072, since 1024 * 64 * 64 would not fit in memory), evicting the least recently used. An
evicted member is sent again, never omitted. State is in memory only; a restart sends every client its members again.

Locking: the tracker owns one `std::mutex`, a strict leaf. `sync_json` calls it while holding `homeserver.mutex`; it never
calls out and nothing that holds it takes the runtime mutex. The order is runtime mutex, then tracker mutex. `begin_request`
runs after the long-poll wait in the run that answers, so a rerun judges redundancy afresh and nothing is recorded for a
run that returns `needs_wait`.

### Negative Consequences

* A client that keeps retrying an old `since` is sent its members every time.
* Not tracked: `/messages` and `/context` (ADR-0451), sliding sync, and anything after a restart.
