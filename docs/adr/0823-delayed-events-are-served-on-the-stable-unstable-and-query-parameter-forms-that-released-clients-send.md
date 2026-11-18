# Delayed events are served on the stable, unstable and query-parameter forms that released clients send

* Status: accepted
* Date: 2026-11-17

## Context and Problem Statement

Delayed events (MSC4140) let a client ask the server to send an event later, and to cancel or postpone it. MatrixRTC
uses them to schedule a call membership leave, so that a participant whose client vanished is removed from the call.
The MSC merged on 2026-09-08 and the feature is in matrix-spec `main` (commit `7198bf6724`, 2026-11-13) as v1.20. It
is not in the vendored v1.19 specification, so it has no conformance scenarios here. Which request forms does the
server serve?

The released clients, read at their release tags on 2026-11-17, do not send the spec's stable paths:

* Element X iOS and Android 26.11.0 (matrix-rust-sdk `3ff03638`, ruma `0ed7fba3`) and Element Call 0.28.2 running
  standalone send only the query form, `?org.matrix.msc4140.delay=` on the ordinary `/send` and `/state` routes.
  Element X manages an event with `POST .../org.matrix.msc4140/delayed_events/{delayId}` and the action in the body.
* Element Web 1.12.35 (matrix-js-sdk 45.1.0) tries the unstable dedicated path
  `.../org.matrix.msc4140/rooms/{roomId}/delayed_event/{eventType}/{txnId}` first and falls back to the query form on
  `M_UNRECOGNIZED`. It manages with `POST .../org.matrix.msc4140/delayed_events/{delayId}/{send|cancel|restart}`.
  Element Call 0.28.2 pins matrix-js-sdk commit `3f05dc4d`, which schedules with the query form and manages with the
  same path-form `POST`.
* lk-jwt-service 0.10.0 manages a delegated leave as an application service acting for the user, on the same
  unstable management path.
* Every client reads only the `org.matrix.msc4140` flag in `unstable_features`; matrix-js-sdk refuses to use the
  feature without it.

## Decision Outcome

Chosen option: "serve every form a released client sends, plus the spec's stable forms", because a server that serves
only the stable paths schedules nothing for the clients that exist.

| # | Method and path | Who sends it |
|---|---|---|
| S1 | `PUT /_matrix/client/v3/rooms/{roomId}/delayed_event/{eventType}/{txnId}` | spec, stable; no released client yet |
| S2 | `PUT /_matrix/client/unstable/org.matrix.msc4140/rooms/{roomId}/delayed_event/{eventType}/{txnId}` | Element Web 1.12.35 |
| L1 | `PUT /_matrix/client/v3/rooms/{roomId}/send/{eventType}/{txnId}?org.matrix.msc4140.delay=<ms>` | Element X, standalone Element Call |
| L2 | `PUT /_matrix/client/v3/rooms/{roomId}/state/{eventType}/{stateKey}?org.matrix.msc4140.delay=<ms>`, and the no-state-key and empty-state-key forms the ordinary state route accepts | Element X, standalone Element Call; the path a call's leave is scheduled on today |
| M1 | `POST /_matrix/client/v1/delayed_events/{delayId}/{send\|cancel\|restart}` | spec, stable |
| M2 | `POST /_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delayId}/{send\|cancel\|restart}` | matrix-js-sdk, lk-jwt-service |
| M3 | `POST /_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delayId}` with body `{"action":"send"\|"cancel"\|"restart"}` | Element X; the js-sdk fallback |
| G1 | `GET /_matrix/client/v1/delayed_events/{delayId}` | spec, stable |
| G2 | `GET /_matrix/client/unstable/org.matrix.msc4140/delayed_events/{delayId}` | a matrix-js-sdk method |

M3 exists only under the unstable prefix; `POST /_matrix/client/v1/delayed_events/{delayId}` is not a route. A last
segment other than `send`, `cancel` or `restart` on M1 or M2 is not a route (`404 M_UNRECOGNIZED`).

Every route needs an access token and goes through the standard gate (`M_MISSING_TOKEN`, `M_UNKNOWN_TOKEN`, the
moderation gate for locked and suspended accounts). Application-service masquerade (`?user_id=`) works exactly as on
other routes; lk-jwt-service depends on it.

A request that carries `org.matrix.msc4140.delay` is always taken down the delayed branch, before the ordinary
route's idempotency lookup and before any send. It never falls through to an immediate send, including when the
feature is disabled (then it is `403 M_FORBIDDEN`). A delay that is not a decimal integer of at least 1, or is
repeated, is `400 M_INVALID_PARAM`.

The parameter is honoured only on `PUT .../send/{eventType}/{txnId}` and `PUT .../state/...`. Every other client
route that sends a room event from the caller's body (`POST /_matrix/client/v3/rooms/{roomId}/send` and
`PUT .../redact/{eventId}/{txnId}`) answers `400 M_INVALID_PARAM` when the parameter is present, before anything is
sent and whether or not the feature is enabled, so that no route can send at once a request that asked for a delay.
The parameter's name is percent-decoded before it is compared, so an encoded spelling is recognised. The
application-service `?ts=` parameter is ignored on a delayed request; the event is stamped with the time it is sent.

Management looks an event up by the authenticated user and the delay ID. A delay ID that does not exist and one that
belongs to another user get the same answer, byte for byte: `404 M_NOT_FOUND`, `Delayed event not found.`

Management outcomes, all success bodies `{}`:

| State of the delayed event | `restart` | `cancel` | `send` |
|---|---|---|---|
| scheduled | 200; the delay starts again from now | 200; finalised as cancelled | sends now; 200 and finalised as sent; on failure the status and error an ordinary send gives, and the event stays scheduled with its timer unchanged |
| sent | 409 | 409 | 200 |
| cancelled by the user | 409 | 200 | 409 |
| cancelled because sending failed | 409 | 200 | 409 |
| being sent right now | 409 | 409 | 409 |

The 409 errcode is `M_UNKNOWN`. Released clients treat 404 `M_NOT_FOUND` and any 409 alike as "gone"
(matrix-js-sdk `isDelayedEventGoneError`, lk-jwt-service).

`/versions` carries `org.matrix.msc4140` and `org.matrix.msc4140.stable`, both set to whether the feature is enabled.
`/capabilities` carries `m.delayed_events` and `org.matrix.msc4140.delayed_events`, each
`{"max_delay_ms", "max_scheduled"}`, zeros when disabled. The event a delayed event became carries
`unsigned.delay_id` and `unsigned.org.matrix.msc4140.delay_id` for the user who scheduled it only, and no
`transaction_id`.

## Pros and Cons of the Options

### Serve only the spec's stable paths

* Bad, because no released client calls them: Element X and standalone Element Call would schedule nothing.

### Do not serve the dedicated path and rely on the js-sdk fallback

* Bad, because the fallback needs exactly `M_UNRECOGNIZED`, is permanent for the client's lifetime, and the dedicated
  path is where the spec and clients are going.

### Answer 404 for every finalised delayed event, as Synapse 1.165 does by deleting the row

* Bad, because it loses the spec's idempotent 200 for a repeated action and the stored error. Released clients treat
  409 and 404 alike, so nothing is gained.

### Unauthenticated management, with the delay ID as a bearer capability

Earlier MSC drafts did this, and one other server still accepts it on the path form.

* Bad, because the final MSC and the spec require authentication, every released client sends a token, and
  lk-jwt-service authenticates as an application service. The delay ID is an identifier, never a credential.

### The pre-1.157 Synapse error for a too-large delay

`M_UNKNOWN` with `org.matrix.msc4140.errcode`. It is the only form Element Call 0.28.2's pinned js-sdk recognises.

* Bad, because it is gone from the MSC and from Synapse. The server answers `400` with `M_DELAY_TOO_LARGE` on S1 and
  `ORG.MATRIX.MSC4140_DELAY_TOO_LARGE` on S2, L1 and L2. The cost is confined to an operator who lowers the maximum
  delay below what the client asks for (18 seconds; one hour with MSC4195 delegation): that client joins without a
  delayed leave.

### The listing endpoint

`GET .../delayed_events` is MSC4486.

* Bad, because it is unmerged and no released code calls it. It stays `404 M_UNRECOGNIZED`.

### Cancel a pending delayed state event when another state event with the same type and state key is sent

Earlier drafts did this. Synapse stopped in 1.127 and 1.164.

* Bad, because the client sends its join immediately after scheduling its leave under the same key; the join would
  cancel the leave.

## Consequences

* The unstable and query forms are retired only after released clients stop sending them. Check the client release
  tags again when a spec release containing delayed events is vendored.
* The listing endpoint and sticky events (MSC4354) remain out of scope; the sticky member of the dedicated body is
  ignored.
* Application-service masquerade on the management routes must keep working.
* A new route that sends an event from the caller's body must refuse the delay parameter the same way.
* The user manual tells operators to keep the maximum delay at one hour or more.

## Links

* Related: [ADR-0824](0824-a-delayed-event-is-a-stored-row-kept-after-it-is-finalised-bounded-per-user-and-deleted-with-the-account.md)
* Related: [ADR-0825](0825-a-due-delayed-event-is-sent-by-one-job-through-the-ordinary-send-path-never-early-and-at-least-once.md)
* Related: [ADR-0826](0826-delayed-events-are-on-by-default-with-a-maximum-delay-per-user-caps-and-per-user-rate-limits.md)
* Related: [ADR-0822](0822-the-rtc-transport-is-advertised-as-type-livekit-with-livekit-service-url.md)
