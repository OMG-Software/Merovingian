# Typing expires on a periodic job, with a ceiling for clients and a timeout for federation

* Status: accepted
* Date: 2026-10-22

Technical Story: conformance audit 2026-10-17, R13 (local typing never expired; a non-boolean
`typing` was treated as true)

## Context and Problem Statement

Spec (`PUT /_matrix/client/v3/rooms/{roomId}/typing/{userId}`): "This tells the server that the
user is typing for the next N milliseconds where N is the value specified in the timeout key."
The server ignored `timeout`: a local user's typing lasted until they sent `typing: false` or a
message. Typing learnt from a federated `m.typing` EDU, which carries no timeout, lasted until the
sender's server sent `typing: false`, so a crashed or hostile peer could leave a user typing for
good. When typing ends, the other members' next `/sync` must carry an `m.typing` without the user.

## Decision Drivers

* An expiry must reach a client that is parked in a long-poll `/sync`, not only one that polls.
* Nothing a client or a peer sends may keep a user typing indefinitely.
* Remote servers learn of local typing from our EDU and have no timeout for it.

## Considered Options

* A `PeriodicJob` ("typing-expiry") that removes expired entries and wakes sync waiters
* Removing expired entries lazily whenever `/sync` or sliding sync builds a response
* Honour the client's `timeout` exactly, however long

## Decision Outcome

Chosen option: "a `PeriodicJob`", with three constants in `runtime.hpp`:

* `default_typing_timeout` (30 s) when the client omits `timeout`;
* `max_typing_timeout` (120 s), the ceiling on a client's `timeout`. Clients refresh every 20 to
  30 seconds as the spec recommends, so this is not visible to them;
* `federation_typing_timeout` (60 s) from the latest EDU that set a remote user typing. Remote
  clients refresh within that, and each refresh is forwarded as a new EDU.

Every path that sets an entry to `typing: true` sets `InboundTypingUser::expires_at`.
`homeserver::expire_typing` removes the entries whose expiry has passed and advances the typing
stream position of each room that changed. `expire_typing_notifications` takes `runtime.mutex`,
calls it, publishes the new position to the sync notifier, and sends `typing: false` to the remote
servers in the room for each local user whose typing expired, as a `typing: false` request would.
It returns the time to the earliest pending expiry, kept between 250 ms and 5 s, and the job
sleeps that long. Tests call it with a chosen clock.

The request must carry `typing` as a JSON boolean (`400 M_MISSING_PARAM` when absent,
`400 M_BAD_JSON` otherwise), and `timeout`, when present, a non-negative integer
(`400 M_BAD_JSON`, or `400 M_INVALID_PARAM` when negative). A refused request changes nothing.

### Positive Consequences

* A parked long-poll wakes within about 250 ms of an expiry.
* No client or peer can keep a user typing for more than two minutes without refreshing it.

### Negative Consequences

* One more thread, which wakes at most every 5 s and holds `runtime.mutex` only for a pass over the
  typing entries (at most `max_inbound_typing_entries` remote ones).

## Pros and Cons of the Options

### Lazy expiry in the sync builders

* Good, because it needs no thread.
* Bad, because a client parked in a long-poll is never woken by an expiry, so the indicator stays
  until something else changes in its rooms.
* Bad, because it turns read paths into writers of runtime state.

### Honour any client timeout

* Good, because it is literal.
* Bad, because a timeout of years recreates the bug the audit found.

## Links

* Spec: `docs/matrix-v1.19-spec/client-server-api.md#typing-notifications`
* Uses the `PeriodicJob` of [ADR-0163](0163-appservice-delivery-is-a-durable-outbox-drained-by-one-thread.md)
