# The LiveKit webhook is served on the client listener and trusted only to prompt a check

* Status: accepted
* Date: 2026-11-17

Technical Story: MatrixRTC slice 4, the delegated delayed leave (ADR-0832).

## Context and Problem Statement

LiveKit tells a configured URL about participants joining and leaving by webhook. MSC4195 recommends combining
webhooks with polling for a delegated leave, since webhooks have no delivery guarantee. A webhook is an unauthenticated
HTTP request as far as Matrix is concerned: anyone who can reach the URL can send one. What it may change, and how it
proves it came from the operator's LiveKit, has to be decided.

LiveKit signs each webhook: the `Authorization` header holds an HS256 JWT signed with the API secret, whose `iss` is the
API key, valid for 5 minutes, and whose `sha256` claim is the standard base64 of the SHA-256 of the body. The body is a
`WebhookEvent` in protobuf JSON: `event`, `room.name`, `participant.identity`, `id` and `createdAt` (seconds).

## Decision Drivers

* No state changes on a webhook alone (ADR-0832).
* The check is the one LiveKit's own SDKs make, with nothing weaker.
* A webhook that is replayed, stale or not for a delegation this server recorded does nothing.
* A flood of webhooks, forged or real, costs little.

## Decision Outcome

### Where

`POST /_merovingian/livekit/webhook`, a fixed path on the client listener(s). The operator points LiveKit's
`webhook.urls` at it. The client listener is chosen because the operator's LiveKit already reaches this server's
client API, and the federation listener is for other servers. With the built-in token service off the path is
404 `M_UNRECOGNIZED`, as any unknown route.

### Authentication

In order, each failure answering 401 `M_UNAUTHORIZED` with one text and logging `livekit.webhook.refused` with the
reason:

1. The body is at most 64 KiB (413 above that, before anything is read).
2. `Authorization` is present: a JWT, with or without a `Bearer ` prefix, at most 4096 bytes.
3. The JWT verifies with `crypto::verify_hs256_token` under the API secret, read from its file for this request into a
   `core::SecretBuffer`. The header's `alg` is never read (ADR-0828).
4. `iss` equals `server.rtc.livekit.api_key`.
5. `nbf` is not after now plus 60 seconds and `exp` is after now minus 60 seconds: the token is current, with a
   minute's allowance for clock difference.
6. `sha256` equals the base64 of the body's SHA-256, compared in constant time, so the body is the one LiveKit signed.

### What an authenticated event may do

* Only `participant_joined`, `participant_left` and `participant_connection_aborted` are read. Others are answered
  200 and ignored, so LiveKit does not retry them.
* `createdAt` within 5 minutes of now, and an `id` (at most 128 bytes) not among the last 1024 seen, else ignored. A
  replay within the token's own 5 minutes is caught by the `id`; one after is caught by the token's `exp`.
* The event must name, by `room.name` and `participant.identity`, a delegation this server recorded, created no later
  than `createdAt`, else ignored. Nothing in the body is used otherwise: no Matrix ID is derived from it.
* A match marks that delegation to be checked at the next run of `livekit-delegations` and wakes the job. That is all.

Every authenticated event is answered 200 `{}`.

### Bounds

* The path has the client rate limiter's default per-address limit (600 a minute) and no tighter one: LiveKit sends
  every room and track event of every call from one address, and a webhook refused for its rate only loses a prompt,
  since the job's own checks decide.
* A request costs a secret read, an HMAC and a SHA-256, under `runtime.mutex` only for the delegation lookup.

### Positive Consequences

* Forged, replayed or stale webhooks change nothing, and real ones only bring a check forward.

### Negative Consequences

* LiveKit must be able to reach the client listener's address.
* A webhook signed with the secret but for an event LiveKit never sent (someone holding the secret) can still only
  prompt a check.

## Pros and Cons of the Options

### Serve the webhook on a listener of its own

* Good, because it could be bound to loopback only.
* Bad, because it is a new listener for one route, with its own TLS and configuration, and the signature already
  restricts who can use the route.

### Act on `participant_left` at once

* Good, because the leave is sent sooner by up to one polling interval.
* Bad, because a forged-but-signed or reordered webhook would end a membership that LiveKit still shows connected.

## Links

* Refines [ADR-0832](0832-a-delegated-delayed-leave-is-restarted-while-livekit-shows-the-participant-and-sent-once-it-does-not.md)
* [ADR-0828](0828-livekit-tokens-are-signed-and-verified-only-through-typed-hs256-functions-in-the-crypto-boundary.md)
