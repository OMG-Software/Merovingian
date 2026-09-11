# src/push/ — Push Notifications

Push rule evaluation (Client-Server API) and the outbound Push Gateway API client.

Spec authority:
- Push rules: [client-server-api.md](../../docs/matrix-v1.19-spec/client-server-api.md), "Push notifications"
- Gateway delivery: [push-gateway-api.md](../../docs/matrix-v1.19-spec/push-gateway-api.md)

## Key files

| File | Responsibility |
|---|---|
| `push_rules.cpp` | `parse_push_ruleset` / `evaluate_push_rules`: pure, in-memory rule evaluation against an event |
| `push_gateway_client.cpp` | `PushGatewayClient::notify`: builds and sends `POST /_matrix/push/v1/notify`, parses `rejected_pushkeys` |

The server-default ruleset is in `homeserver/default_push_ruleset.cpp`; delivery scheduling and the
concurrency caps are in `homeserver/room_service.cpp`.

## Rules — non-negotiable

1. **`push_rules.cpp` is pure: no I/O, no database, no locks.** The caller supplies room member
   count, power levels and display name in `PushEvaluationContext`, so evaluation is safe while
   `runtime.mutex` is held.
2. **An unrecognised condition kind never matches** ("Unrecognised conditions MUST NOT match any
   events"). Parse it to `PushConditionKind::unknown`; do not guess.
3. **`.m.rule.master`, when enabled, always wins.** Otherwise kinds are checked in precedence order
   override > content > room > sender > underride, and the first enabled match wins.
4. **A gateway URL is attacker-influenced** — any client can register a pusher pointing anywhere.
   `notify` resolves it through `federation::CachedServerDiscovery`'s SSRF-safe path (private and
   loopback ranges rejected), never a direct DNS lookup or a client-supplied address.
   `TestForcedPushGatewayResolution` is the only bypass and is always empty in production.
5. **The URL must be HTTPS with a path of exactly `/_matrix/push/v1/notify`** —
   `parse_push_gateway_url` enforces this before any request is built.
6. **`notify()` fails closed when `server.push.enabled` is false** (the default): no DNS, no
   connection, no bytes leave the process.
7. **`Device.data` forwards the pusher's registered `data` verbatim except `url` and `format`**, as
   the spec requires ("the data dictionary passed in at pusher creation minus the url key").
8. **This client never touches the database.** The caller owns removing pushers named in
   `rejected_pushkeys`.
9. **Delivery is capped, registration is not.** Background deliveries past
   `k_max_in_flight_push_deliveries` (128) are dropped rather than queued (ADR-0028), and at most
   `k_max_pushers_per_delivery` (10) pushers are contacted per event (ADR-0029). Both caps live in
   `room_service.cpp`; any change to how push is invoked must preserve them.
10. **No network call here runs under the caller's locks**, matching the project rule that
    `runtime.mutex` is never held across a blocking call.

## Testing

- `tests/unit/test_push_rules.cpp`, `tests/unit/test_default_push_ruleset.cpp` — evaluation and default ruleset
- `tests/unit/test_push_gateway_client.cpp` — request building, response parsing, SSRF gate
- `tests/unit/test_push_pusher_store.cpp` — pusher persistence
- `tests/conformance/test_push_notifications_conformance.cpp` — spec conformance
- `tests/integration/test_push_delivery_flow.cpp` — end-to-end delivery

## Key docs

- `docs/architecture.md` — "Fire-and-forget background work" and the push-notifications entry
- [ADR-0010](../../docs/adr/0010-run-fire-and-forget-work-as-parked-futures.md) ·
  [ADR-0028](../../docs/adr/0028-drop-push-deliveries-at-the-concurrency-cap.md) ·
  [ADR-0029](../../docs/adr/0029-bound-pusher-delivery-rather-than-registration.md)
