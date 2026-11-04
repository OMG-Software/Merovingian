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
  it, and counts only when a later request's `since` is at or past that token on all three components
* No record: always send every timeline sender's member (valid, wasteful)

## Decision Outcome

Chosen option: the acknowledgement-based `sync::LazyMemberTracker`.

The rejected sent set breaks on this sequence. Response R1 (`since` T0) carries bob's member event and is lost. The
client retries with T0. R2 is `limited`, so bob's earlier events fall into the gap and bob is no timeline sender: R2 does
not carry bob, and the sent set still says he was sent. Bob next speaks in a response with `since` T2; the set says
"sent", so his member is skipped and the client has never seen it. The tracker prevents this by two rules:

* A tracked member is redundant only if its stored event ID equals the current member event ID and the request's `since`
  covers the stored token on `event_ordering`, `membership_ordering` and `sync_stream_id`.
* At the start of a request with a `since`, every entry that `since` does not cover is deleted. A retry of an older token
  proves the client never received that response. A request with no `since` deletes everything under its key.

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
