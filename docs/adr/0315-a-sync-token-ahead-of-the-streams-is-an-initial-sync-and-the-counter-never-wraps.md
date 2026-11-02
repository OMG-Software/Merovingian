# A /sync token ahead of the streams is an initial sync, and the sync stream counter never wraps

* Status: accepted
* Date: 2026-11-02

Technical Story: security audit run-2 F-03, `GET /sync?since=0_0_ffffffffffffffff` poisoned the server-wide counter

## Context and Problem Statement

`sync_json` passed the `since` token's sync component to `ensure_sync_stream_id_ahead_of`, which raised the
server-wide counter to it and persisted the result. The path dated from before the watermark table existed, when
a restart could lose ephemeral positions. The token is client input and carries no signature, so any user could
set the counter to 2^64-1. The next allocation wrapped to 0, and every row after that sat at or below other
users' tokens: not delivered, and for device-targeted to-device messages (E2EE room keys among them) deleted as
acknowledged.

The watermark is now written on every allocation and the counter is restored from it and from durable rows, so
the rollback the path recovered from no longer happens. A token ahead of the server means a forged token or a
database restored from a backup.

`GET /sync` lists no error for a token the server cannot serve, and `since` is only a "should" for an earlier
`next_batch`. `M_UNKNOWN_POS` belongs to MSC4186, not v1.19.

## Considered Options

* Serve a token ahead of any stream as an initial sync, the same as an undecodable token
* Answer 400 `M_UNKNOWN_POS`, as sliding sync does
* Clamp the token to the current position and serve an incremental sync

## Decision Outcome

Chosen option: "Serve as an initial sync", because it conforms to the spec's error list, it matches what this
endpoint already does with a token it cannot decode, and a client recovers from it without knowing anything
happened. A 400 is outside the endpoint's contract, and classic clients retry a failing sync indefinitely rather
than dropping their token. Clamping silently treats everything between the clamp and the token as seen, which is
the bug the sliding sync handler's comment records. Sliding sync keeps `M_UNKNOWN_POS`, which MSC4186 defines.

No client input moves server-wide stream state, and `ensure_sync_stream_id_ahead_of` is removed so nothing can.

`allocate_sync_stream_id` throws `std::overflow_error` at `INT64_MAX`, the largest value its BIGINT rows can hold,
leaving the counter where it was. Saturating was rejected because it reuses an id, and reused ids are what deleted
messages. Returning an error through its 25 callers was rejected because, with the ratchet gone, the ceiling needs
2^63 allocations or a database edited by hand; a request that hits it fails rather than corrupts.

Many paths store something and then allocate, some inside helpers, and the two ways out at the ceiling are not equal:

* Event, room and membership writes are refused by the store once the counter is within `sync_stream_write_reserve`
  (2^20) of the ceiling. They already report failure to every caller, so each path answers with its existing error.
  Reordering every path was rejected: it is scattered, and the next path written would have to know.
* Key, signature and device-name uploads check the same reserve before they store, because a client can retry them.
  A check for one remaining position was rejected: handlers do not hold the runtime lock across it, so it can race,
  and a second threshold buys nothing 2^63 positions from the first.
* Logout and device deletion finish, with the undelivered device-list change logged. A check there was rejected: it
  would stop a user revoking access on a server already in trouble, and revoking access outweighs a notification.
  Local observers miss that change, so their copy of the device list stays stale until the next one.

Writes that allocate first (receipts, presence, to-device, account data, typing) fail with nothing stored, and the
exception is caught at `handle_client_server_request`, which answers 500. Without that catch the connection is dropped
without an answer. The federated invite handler, `forget_room` and PDU ingest catch it themselves, the first and last
because their callers can be a worker waiting on an IPC reply.

### Positive Consequences

* One user's token cannot affect another user's stream.
* Stream ids are only ever skipped, never reused.

### Negative Consequences

* A client whose token is ahead after a database restore gets a full initial sync.
* A client that stays offline from a restore until the counter has passed its token cannot be told apart from a
  current one. Rows numbered after the restore at or below that token count as seen, and device-targeted to-device
  rows among them are purged undelivered. Any sync before then replaces the token, so only a client offline
  throughout is affected. `ensure_sync_stream_id_ahead_of` did not cover this client either, as it acted only on a
  presented token. Telling such a token apart needs something the restore does not bring back, so it is left open;
  the user manual warns operators.
* A database already holding a poisoned watermark refuses every sync-stream write until an operator repairs it.
  It is not repaired automatically: lowering the counter would reuse ids that clients may have seen.
