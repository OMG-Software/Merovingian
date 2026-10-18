# Send-to-device commits its local messages and its transaction ID together

* Status: accepted
* Deciders: James Chapman, Claude Code
* Date: 2026-10-17

Technical Story: audit finding R02, `fix/audit-r02-to-device-atomic`

## Context and Problem Statement

`PUT /_matrix/client/v3/sendToDevice/{eventType}/{txnId}` queued each local
recipient's message through `push_to_device_message`, discarded its result, then
recorded the client transaction (`store_client_txn`, also unchecked) and answered
200. A failed database commit therefore returned 200, and when the transaction
record did commit, the client's retry hit the replay check and got 200 again with
nothing delivered: the message was lost while reported sent. The Matrix v1.19
Client-Server API says 200 means the message was successfully sent, and the
transaction ID exists so a retry is idempotent. How should the handler answer when
part of the work fails, so a retry is safe?

## Decision Drivers

* A 200 must mean every local message is durably queued and the transaction is recorded.
* A client that is told the request failed must be able to retry the same
  transaction ID and have it processed, delivering each message exactly once.
* A request can fan out to many recipients (`"*"` expands to every device), so a
  per-message commit cannot be made all-or-nothing.
* Remote delivery is a federation queue write, not part of the local database
  transaction.

## Considered Options

* One atomic commit of every local to-device row and the `client_txn_ids` row,
  with the remote EDUs queued first
* Return 500 after a partial delivery, leaving the rows that did commit
* Commit the messages one by one, then record the transaction in a separate write

## Decision Outcome

Chosen option: "one atomic commit, remote first".

`database::enqueue_to_device_messages_with_client_txn` builds every DELETE
(per-recipient age and count eviction, CSAZ-10) and INSERT statement plus the
transaction INSERT, commits them with `commit_persistent_transaction`, and updates
the in-memory mirror only after that commit succeeds. A failure leaves memory and
disk unchanged and the transaction unrecorded; the handler answers `500 M_UNKNOWN`.

The m.direct_to_device EDUs are queued before anything local is committed, and a
destination that cannot be queued (`dispatch_edu_to_server` returns false) fails
the request with nothing local committed. A retry sends the EDUs again. That is
safe only because the EDU's `message_id` is the client transaction ID, which the
receiving server uses for idempotence (server-server API, "Send-to-device
messaging"; this server dedupes on `(origin, message_id)` in
`EduIdempotenceWindow`). The ordering matters: with local first, a remote failure
after the local commit would leave the transaction recorded, so the retry would be
replayed and the remote message lost; with remote first, the worst outcome is a
duplicate EDU the receiver discards.

### Positive Consequences

* 200 is only ever returned for fully queued messages; a retry is processed.
* No window in which the transaction is recorded without its messages, or the
  messages are queued without the transaction.

### Negative Consequences

* A remote recipient whose EDU cannot be queued while federation is enabled now
  fails the request with 500 instead of being silently dropped. With
  `security.federation.enabled = false` a remote recipient can never be reached,
  so it is discarded like an unknown local recipient and the request still
  succeeds; failing it would only make the client retry forever.
* One transaction can carry many statements for a wide `"*"` fan-out.
* Stream ids allocated for a failed commit are skipped (never reused).

## Pros and Cons of the Options

### Return 500 after a partial delivery

* Good, because it needs no new store function.
* Bad, because the rows that did commit are delivered again on retry (duplicates)
  or, if the transaction was recorded, never redelivered (loss).

### Record the transaction in a separate write

* Good, because it reuses `store_client_txn`.
* Bad, because a crash or failure between the two writes leaves the messages queued
  with no transaction record (a retry duplicates them), or the reverse order records
  the transaction with no messages (a retry is replayed and the message is lost).

## Links

* Refines [ADR-0105](0105-silently-discard-sendtodevice-to-unknown-local-recipients.md)
  (recipient filtering is unchanged) and
  [ADR-0117](0117-bound-to-device-queues-by-recipient-count-and-age.md) (the evictions
  now commit in the same transaction)
