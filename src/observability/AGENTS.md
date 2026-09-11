# src/observability/ — Observability Module

Structured logging and audit trail for the server.

## Key files

| File | Responsibility |
|---|---|
| `observability.cpp` | Audit event types and category enum, admin route matching (`admin_routes`/`match_admin_route`), health and Prometheus metrics snapshots, correlation context (`CorrelationScope`), and automatic log-field redaction (`log_field_is_sensitive`, `redact_log_value`, `redact_log_message`) |
| `logger.hpp` (header-only) | Structured logger with level filtering; sinks to stdout/file |

## Log level policy

| Level | When to use |
|---|---|
| `ERROR` | Service cannot continue; operator action required |
| `WARN` | Unexpected condition; service degraded but continuing |
| `INFO` | Major lifecycle events: startup, shutdown, TLS cert load, migration applied |
| `DEBUG` | Per-request detail, useful for diagnosing a single failure |
| `TRACE` | High-frequency detail (per-message, per-frame); disabled in release builds |

Avoid promoting DEBUG-level detail to INFO — INFO is what operators see in production logs.

## Audit events

Security-relevant events must be emitted as structured audit log entries (not plain log lines).
Two persistence tiers exist — see `docs/observability-audit.md` for the full catalogue and the
durability distinction:

- **Durable** (via `append_local_audit`, `src/homeserver/local_services.cpp` — written to the
  `audit_log` table): login success/failure (`auth.login`, `login.rejected`), token
  invalidation/rejection (`auth.logout`, `access_token.rejected`), client-server rate-limit
  rejections (`rate_limit.exceeded`, appended from `src/homeserver/client_server.cpp`), and media
  quarantine (`media.quarantined`, `media.upload_quarantined`).
- **In-memory only, not durable** (via `audit_federation`, `src/federation/inbound_request.cpp` —
  appended to `FederationRuntimeState::audit_events`, a bounded deque, never to the database):
  federation request authenticated/rejected (`federation.accepted`, `federation.rejected`,
  `federation.acl_rejected`, etc.). These do not survive a restart and are not returned by
  `GET /_merovingian/admin/audit`. Do not assume a `federation.*` audit call gives the same
  durability guarantee as `append_local_audit` — if the event needs to survive a restart or be
  queryable, it needs its own path to `database::append_audit_event`.

## Rules

- **Never log secret material.** No tokens, passwords, private keys, or full request bodies. Do
  not truncate a secret to a "safe prefix" for logging — a prefix of the real secret is still
  live secret material. Use automatic redaction (fields flagged sensitive, or matched by
  `log_field_is_sensitive`, render as `<redacted>` via `redact_log_value`/`redact_log_message`)
  or a purpose-built one-way summary such as `auth::redacted_token_for_log` (`src/auth/token.cpp`),
  which buckets token length into coarse size classes instead of disclosing length or bytes.
- Log the `user_id` and `device_id` (not the token) for authenticated request traces.
- Every new log call added to security-sensitive paths must be reviewed in `docs/observability-audit.md`.

## Key doc

- `docs/observability-audit.md` — audit event catalogue and log field schema
