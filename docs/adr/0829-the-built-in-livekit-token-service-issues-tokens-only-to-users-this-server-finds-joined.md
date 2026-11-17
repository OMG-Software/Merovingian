# The built-in LiveKit token service issues tokens only to users this server finds joined

* Status: accepted
* Date: 2026-11-17

Technical Story: MatrixRTC slice 4. The owner chose the homeserver flow only, the external service kept but mutually
exclusive, users of other servers relayed out and admitted subscribe-only, and delegated delayed leave implemented.

## Context and Problem Statement

ADR-0822 lets the operator name an external MatrixRTC authorisation service (Element's `lk-jwt-service`). MSC4195 also
lets the homeserver issue LiveKit tokens itself (`POST .../rtc/livekit/get_token`), so no second service, OpenID
round trip or application service is needed. Issuing them means:

* holding the LiveKit API secret, the one secret that controls the SFU;
* deciding who may join which LiveKit room;
* calling LiveKit.

Released Element Call (0.28.2) uses this "homeserver flow" for a transport that has a `url` and no
`livekit_service_url`. It sends `POST /_matrix/client/unstable/io.element.msc4195/rtc/livekit/get_token` with
`{url, room_id, slot_id, member_id, server_name}` and connects to the transport's `url` with the `jwt` it gets back.

## Decision Drivers

* A token goes only to a caller this server authenticated and finds joined to the room, by its own current state, never
  by anything the request claims.
* The SFU never sees a Matrix ID or room ID.
* The secret is never held for the life of the process, logged, or put in a response.
* Nothing a request carries decides where this server connects.

## Considered Options

* Keep only the external service (ADR-0822).
* The built-in service, alongside the external one, both allowed at once.
* The built-in service, or the external one, never both.

## Decision Outcome

Chosen option: "the built-in service, or the external one, never both". Two ways to authorise calls would leave it
unclear which one a client is sent to, so a configuration with both is refused at start-up.

### Configuration

The keys below are all restart-required, read at start-up, and refused, never repaired, by `validate()`:

| Key | Rule |
|---|---|
| `server.rtc.livekit.url` | The SFU's `wss` URL |
| `server.rtc.livekit.api_url` | `https`, or `http` only to a loopback IP literal |
| `server.rtc.livekit.api_key` | 1 to 128 of `A-Za-z0-9_-.` |
| `server.rtc.livekit.api_secret_file` | An owner-only file; the start-up check is `validate_existing_secret_file_metadata`, as for every secret file |
| `server.rtc.livekit.token_lifetime` | 60 s to 1 h, default 1 h |

* The four keys `url`, `api_url`, `api_key` and `api_secret_file` go together.
* With `server.rtc.livekit.service_url` they are refused.
* The secret is read for each token with `platform::read_secure_secret_line` into a `core::SecretBuffer`, used to sign,
  and wiped before the response. The `crypto/LiveKitToken` signers refuse a secret shorter than 32 bytes (ADR-0828), so
  a short one is a 500 and an error log naming no secret.

### Advertisement

* `GET .../rtc/transports` lists `{"type":"livekit","url":<server.rtc.livekit.url>}`. The stable path also lists
  `{"type":"m.livekit","url":...}` after it; MSC4195 names that type, and released clients read only `livekit`.
* `org.matrix.msc4143.rtc_foci` in the well-known document stays for the external service only. The clients that read
  it know only the OpenID flow.
* `/versions` gains `org.matrix.msc4195` and `org.matrix.msc4195.stable`. Each is true exactly when the routes are
  served.

### Routes

* `POST /_matrix/client/v1/rtc/livekit/get_token` and its unstable `io.element.msc4195` path, authenticated.
  * A locked account gets the gate's 401.
  * A suspended account gets the gate's 403 `M_USER_SUSPENDED`: joining a call is participation.
  * Without the built-in service the route answers 404 `M_UNRECOGNIZED`.
* The body is a JSON object with string members `url` (at most 2048 bytes), `room_id`, `slot_id` and `member_id` (each
  1 to 255 bytes, valid for JSON, `room_id` starting `!`), and an optional `server_name`.
  * A missing member is 400 `M_MISSING_PARAM`.
  * Anything else wrong is 400 `M_INVALID_PARAM`.
  * A body that is not an object is 400 `M_BAD_JSON`.
* `server_name` absent or equal to this server's name asks for this server's SFU.
  * `url` must then equal `server.rtc.livekit.url` byte for byte, else 400 `M_INVALID_PARAM` (MSC4195). It is never
    fetched.
  * Another server's name is relayed to that server over federation, as ADR-0831 describes; its `url` is that
    server's to judge.

### Authorisation

* The caller's `memberships` row for `room_id` must say `join`.
  * That row is this server's projection of the room's current `m.room.member` state, written in the same transaction
    as the event (ADR-0126).
  * An unknown room and a room the caller is not joined to are the same 403 `M_FORBIDDEN`.
  * No field of the request is consulted.
* The caller's own token always has `canPublish` and `canPublishData` true.
* Rate limit: 60 a minute per user on each path (built in, `client_rate_limits.per_user.<path>` overrides). The global
  bound is the ADR-0079 outbound budget each token's LiveKit call takes.

### Names

* The LiveKit room is `base64nopad(SHA-256(canonical JSON [room_id, slot_id]))`.
* The identity is the same over `[user_id, member_id]`, as MSC4195 specifies and its vectors test.
* The one exception is the slot `m.call#ROOM`, which is hashed as `m.call#room`. Released Element Call sends the first
  on the unstable path, MSC4195 names the second, and lk-jwt-service folds them so old and new clients meet in one
  LiveKit room. No other value is folded.

### Calling LiveKit

* Before a publishing token is issued, the room is created with `CreateRoom` (MSC4195), as ADR-0830 describes.
* The call takes an ADR-0079 slot first (none is 429 `M_LIMIT_EXCEEDED` with `retry_after_ms`) and runs under one
  10-second deadline, clamped by `remote_timeout`.
* `runtime.mutex` is released for the call only.
* Any failure (unreachable, timeout, a non-200 answer, an answer over 16 KiB) is 502 `M_UNKNOWN`, and no token is
  issued.

### Answer and logging

* The answer is `{"jwt": <token>}`.
* The `livekit` logger records `livekit.token.issued`, `livekit.token.refused`, `livekit.create_room_failed` and
  `livekit.secret_unavailable`. Each carries `user_id` and `room_id`, and a reason where there is one. It never
  records the token, the secret, the slot or the member ID (which carries a device ID).

### Positive Consequences

* A deployment needs only LiveKit: no `lk-jwt-service`, no application service registration, no OpenID exchange, and
  no second copy of the secret.
* Who may join is decided by the server that holds the room state.

### Negative Consequences

* This server now holds the LiveKit API secret, and the threat model records it.
* The OpenID flow (`/sfu/get`) is not served. A client that knows only that flow needs the external service.

## Pros and Cons of the Options

### Keep only the external service

* Good, because the secret stays out of this process.
* Bad, because the external service decides membership by asking the homeserver over OpenID and a well-known lookup.
  It runs as an application service to do delegated leave, and its identity for `/sfu/get` is the raw Matrix ID.

### Both at once

* Bad, because a client is told about one of two, and the operator cannot tell which.

## Links

* Supersedes in part [ADR-0822](0822-the-rtc-transport-is-advertised-as-type-livekit-with-livekit-service-url.md),
  which said there is no `/rtc/livekit/*` route; its external service keeps working unchanged.
* Refined by [ADR-0830](0830-every-call-to-livekit-goes-to-the-configured-address-with-a-token-of-its-own.md) and
  [ADR-0831](0831-a-federated-livekit-token-request-is-judged-by-main-and-answered-subscribe-only.md)
* [ADR-0828](0828-livekit-tokens-are-signed-and-verified-only-through-typed-hs256-functions-in-the-crypto-boundary.md)
* [MSC4195](https://github.com/matrix-org/matrix-spec-proposals/blob/6d49798949e1b31023565d4ff1c7fe10f4cacf83/proposals/4195-matrixrtc-livekit.md)
