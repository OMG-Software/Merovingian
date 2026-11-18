# Delayed events are on by default, with a maximum delay, per-user caps and per-user rate limits

* Status: accepted
* Date: 2026-11-17

## Context and Problem Statement

Delayed events ([ADR-0823](0823-delayed-events-are-served-on-the-stable-unstable-and-query-parameter-forms-that-released-clients-send.md))
hold server memory and database rows for each scheduled and finalised event, and a call restarts its delayed event
every 4 to 5 seconds. Should the feature be on, and what bounds it?

## Decision Outcome

Chosen option: "on by default, bounded per user, with the limits in a restart-required configuration section", because
MatrixRTC calls leave vanished participants listed without it and every limit has a safe default.

| Key | Default | Range |
|---|---|---|
| `server.delayed_events.enabled` | `true` | boolean |
| `server.delayed_events.max_delay_ms` | `86400000` (24 hours) | 1000 to 2678400000 (31 days) |
| `server.delayed_events.max_scheduled_per_user` | `100` | 1 to 1000 |
| `server.delayed_events.max_finalised_per_user` | `100` | 1 to 1000 |

* Every key is validated at parse time and is restart-required: the limits are snapshotted at start-up like
  `server.client_api.*`.
* Disabled: scheduling is `403 M_FORBIDDEN` (`Delayed events are not enabled on this homeserver.`), `/versions` flags
  are false and `/capabilities` carries zeros. Already-scheduled events are still sent and can still be managed.
* A delay over `max_delay_ms` is `400` (`M_DELAY_TOO_LARGE` on S1, `ORG.MATRIX.MSC4140_DELAY_TOO_LARGE` on S2, L1 and
  L2). A user at `max_scheduled_per_user` gets `429 M_LIMIT_EXCEEDED` with `retry_after_ms` and a `Retry-After`
  header set to the time until the user's next scheduled send, rounded up to a whole second and at least 1.
  `max_finalised_per_user` bounds the finalised rows kept per user, with the fixed 7-day age
  ([ADR-0824](0824-a-delayed-event-is-a-stored-row-kept-after-it-is-finalised-bounded-per-user-and-deleted-with-the-account.md)).
* `content` is held to the event size limit (65,536 bytes); a larger one is `413 M_TOO_LARGE`.
* Rate limits. The global limiter runs before dispatch as for every route, and each new path template is its own
  bucket. Management (M1, M2, M3) and lookup (G1, G2) have a built-in per-address refinement of 3000 per 60 seconds
  (many users behind one address, and lk-jwt-service manages every delegated leave from one address) and a built-in
  per-user refinement of 120 per 60 seconds (a call restarts every 4 to 5 seconds, 12 to 15 a minute per device in a
  call). The dedicated scheduling paths (S1, S2) use the generic per-address tier and a built-in per-user 60 per 60
  seconds. The legacy forms (L1, L2) share the ordinary `/send` and `/state` buckets. All are overridable through
  `client_rate_limits.*`.

## Pros and Cons of the Options

### Off by default

Synapse leaves it off: an unset `max_event_delay_duration` disables it.

* Bad, because MatrixRTC calls leave vanished participants listed without it, and every limit has a safe default.

### A value of `0` meaning disabled instead of an `enabled` key

* Bad, because the range check on the other keys is simpler without it, and the capability's "0 means disabled" is
  derived from `enabled`.

### A server-wide cap on scheduled events

* Bad, because one user could then exhaust it for everyone. The bound is per user.

### A new rate-limit tier

* Bad, because built-in per-user and per-address refinements on the new path templates are enough and stay
  overridable through `client_rate_limits.*`.

### Reloadable keys

* Bad, because the limits are snapshotted at start-up like `server.client_api.*`.

## Consequences

* An operator running Element Call keeps `max_delay_ms` at one hour (3600000) or more; the user manual says so.
* Disabling the feature stops new scheduling; it does not cancel events already scheduled.
* A new delayed-events path template gets its own rate-limit bucket and an HTTP-3 scenario row.

## Links

* Related: [ADR-0823](0823-delayed-events-are-served-on-the-stable-unstable-and-query-parameter-forms-that-released-clients-send.md)
* Related: [ADR-0824](0824-a-delayed-event-is-a-stored-row-kept-after-it-is-finalised-bounded-per-user-and-deleted-with-the-account.md)
* Related: [ADR-0825](0825-a-due-delayed-event-is-sent-by-one-job-through-the-ordinary-send-path-never-early-and-at-least-once.md)
