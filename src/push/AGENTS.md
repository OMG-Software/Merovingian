# src/push/ — Push Notifications

Push rule evaluation (Client-Server API) and the outbound Push Gateway API client.

Spec authority:
- Push rules: [client-server-api.md](../../docs/matrix-v1.19-spec/client-server-api.md), "Push notifications"
- Gateway delivery: [push-gateway-api.md](../../docs/matrix-v1.19-spec/push-gateway-api.md)

## Key files

| File | Responsibility |
|---|---|
| `push_rules.cpp` | `parse_push_ruleset` / `evaluate_push_rules`: pure, in-memory rule evaluation against an event |
| `user_push_rules.cpp` | `UserPushRules`: one user's rules over the server defaults; the Push Rules API's create, order, delete, enable and re-action edits, and their validation and bounds (R19, ADR-0204) |
| `push_gateway_client.cpp` | `PushGatewayClient::notify`: builds and sends `POST /_matrix/push/v1/notify`, parses `rejected_pushkeys` |
| `gateway_circuit_breaker.cpp` | `GatewayCircuitBreaker`: per-host consecutive-failure circuit with a cooldown and one probe per window (OUT-3) |
| `push_retry_queue.cpp` | `PushRetryQueue`, `push_retry_backoff`, `push_delivery_should_retry`: the bounded queue of notifications to send again, and when (R14, ADR-0206) |

The server-default ruleset is in `homeserver/default_push_ruleset.cpp`; delivery scheduling and the
concurrency caps are in `homeserver/room_service.cpp`; every attempt and the retry job are in
`homeserver/push_retry.cpp`.

## Rules — non-negotiable

1. **`push_rules.cpp` is pure: no I/O, no database, no locks.** The caller supplies room member
   count, power levels and display name in `PushEvaluationContext`, so evaluation is safe while
   `runtime.mutex` is held.
2. **An unrecognised condition kind never matches** ("Unrecognised conditions MUST NOT match any
   events"). Parse it to `PushConditionKind::unknown`; do not guess.
3. **`.m.rule.master`, when enabled, always wins.** Otherwise kinds are checked in precedence order
   override > content > room > sender > underride, and the first enabled match wins.
4. **A gateway URL is attacker-influenced** — any client can register a pusher pointing anywhere.
   `notify` resolves it through `federation::CachedServerDiscovery::lookup_addresses_filtered`,
   which rejects private, loopback, link-local, CGNAT, NAT64, multicast, and reserved addresses
   before any outbound connection is attempted. Never perform a direct DNS lookup or accept a
   client-supplied address. `TestForcedPushGatewayResolution` is the only bypass and is always
   empty in production.
5. **The URL must be HTTPS with a path of exactly `/_matrix/push/v1/notify`** —
   `parse_push_gateway_url` enforces this before any request is built.
6. **`notify()` fails closed when `server.push.enabled` is false** (the default): no DNS, no
   connection, no bytes leave the process.
7. **`Device.data` forwards the pusher's registered `data` verbatim except `url` and `format`**, as
   the spec requires ("the data dictionary passed in at pusher creation minus the url key").
8. **This client never touches the database.** The caller owns removing pushers named in
   `rejected_pushkeys`.
9. **Delivery and registration are both capped.** Background deliveries past
   `server.push.max_in_flight_deliveries` are dropped rather than queued (ADR-0028), each recipient
   has an in-flight cap of its own, at most `server.push.max_pushers_per_delivery` pushers are
   contacted per event (ADR-0029), `POST /pushers/set` refuses a user's pusher beyond
   `server.push.max_pushers_per_user`, and `GatewayCircuitBreaker` skips a gateway host that
   could not be reached several times in a row (ADR-0151, OUT-3). Only a transport failure counts
   (`gateway_circuit_outcome`); never count an HTTP answer such as a 5xx, which concerns one
   notification on a host other users share. The delivery caps and the breaker are applied in
   `room_service.cpp`; any change to how push is invoked must preserve them.
10. **No network call here runs under the caller's locks**, matching the project rule that
    `runtime.mutex` is never held across a blocking call.
11. **Glob matching stays linear and never uses `std::regex`** (ADR-0175). Evaluation runs per
    local recipient, per event, under `runtime.mutex`, on values the sender controls. Do not
    allocate per character or try every substring pair. The `[push][security][sp01]` scenario
    in `tests/unit/test_push_rules.cpp` checks the matchers against the old implementation on
    seeded random cases; a change to the matchers must keep it passing.
12. **A user's rules are bounded before they are stored, and again when they are read**
    (ADR-0204). `UserPushRules` refuses a rule past `server.client_api.max_push_rules_per_user`
    and any rule over the per-rule bounds in `user_push_rules.hpp` (ID, pattern and string
    lengths, condition and action counts, canonical size). The stored `m.push_rules` content is
    read through the same validator, so a rule that would be refused now is skipped. Do not add a
    path that evaluates stored rules without going through `UserPushRules`
    (`homeserver::load_user_push_rules` / `load_push_ruleset`).
13. **Failed notifications are retried from the bounded queue only** (R14, ADR-0206). An HTTP error
    or an unreachable gateway is retried with exponential backoff (`push_retry_backoff`) up to
    `push_retry_max_retries`; nothing else is (`push_delivery_should_retry`). The queue's bounds
    (`push_retry_queue_capacity`, `push_retry_per_user_capacity`) drop, never block. A rejected
    pushkey drops its queued retries. Every attempt goes through `homeserver::attempt_push_delivery`,
    which keeps the circuit breaker and rejection handling in one place; never sleep in a delivery
    task to retry, which would hold an in-flight slot (ADR-0028).

## Testing

- `tests/unit/test_push_rules.cpp`, `tests/unit/test_default_push_ruleset.cpp` — evaluation and default ruleset
- `tests/unit/test_user_push_rules.cpp` — user rules over the defaults: ordering, refusals, bounds, round trip
- `tests/conformance/test_push_rules_api_conformance.cpp` — Push Rules API and `m.push_rules`
- `tests/unit/test_push_gateway_client.cpp` — request building, response parsing, SSRF gate
- `tests/unit/test_push_retry_queue.cpp` — backoff, retry classification, queue bounds and concurrency
- `tests/unit/test_push_pusher_store.cpp` — pusher persistence
- `tests/conformance/test_push_notifications_conformance.cpp` — spec conformance
- `tests/integration/test_push_delivery_flow.cpp` — end-to-end delivery

## Key docs

- `docs/architecture.md` — "Fire-and-forget background work" and the push-notifications entry
- [ADR-0010](../../docs/adr/0010-run-fire-and-forget-work-as-parked-futures.md) ·
  [ADR-0028](../../docs/adr/0028-drop-push-deliveries-at-the-concurrency-cap.md) ·
  [ADR-0029](../../docs/adr/0029-bound-pusher-delivery-rather-than-registration.md)
