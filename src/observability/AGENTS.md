# src/observability/ — Observability Module

Structured logging and audit trail for the server.

## Key files

| File | Responsibility |
|---|---|
| `observability.cpp` | Audit event types and category enum, admin route matching (`admin_routes`/`match_admin_route`), health and Prometheus metrics snapshots, correlation context (`CorrelationScope`), and automatic log-field redaction (`log_field_is_sensitive`, `redact_log_value`, `redact_log_message`), control-character escaping (`escape_log_controls`) and the field-value length cap (`cap_log_field_value`, `render_log_field_value`) |
| `logger.hpp` (header-only) | Structured logger with level filtering; sinks to stdout/file; writer threads only after `start_writers()` |

## Writer threads (ADR-0082)

`SingleLog` starts **no thread** in its constructor. Until `start_writers()` is called every
line is written synchronously on the calling thread (stdout under a mutex, and the log file
when one is open), so a message logged early is never lost and cannot deadlock. After
`start_writers()` lines go through the bounded queues and the two writer threads, as before.

- A process that hardens itself (`merovingian-fed-worker`, `merovingian-server`) calls
  `SingleLog::instance().start_writers()` only **after** Landlock, seccomp and the runtime
  controls are applied. A thread that exists earlier escapes the Landlock ruleset (see
  `src/platform/AGENTS.md`, rule 6).
- A process that never calls it (`--check-config`, `--dry-run`, `merovingian-db-migrate`, unit
  tests) still logs correctly, with no logger threads.
- `start_writers()` returns `false` and leaves the logger synchronous if a thread cannot be
  created; callers log a warning and carry on.
- Do not move the `start_writers()` call earlier, and do not start a thread from anywhere in the
  logger's constructor or in a `static` initialiser.

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

- **One log record is one physical line.** `SingleLog::make_log_line` passes the module and
  message through `escape_log_controls` (AUTH-9), so control characters in any logged value are
  written as printable escapes. Write log records only through `SingleLog`; never write log
  data to `std::cout`/`std::cerr` directly, never remove that escaping, and do not pre-escape
  values at call sites. `redact_log_message` must keep treating every whitespace character as a
  token boundary, or a sensitive last field swallows the record's `\n`.
- **Every structured field value is capped at `max_log_field_value_bytes` (2048) of emitted
  bytes** (AUTH-9). `render_log_field_value` (redact, then `cap_log_field_value`) is the only
  way a field value may be put on a line; `diagnostic_message` and `structured_log_summary`
  use it. A new place that renders `StructuredLogField` values must call it too, never
  `redact_log_value` alone. The cap is measured after escaping, cuts on a code-point or whole
  escape boundary, and appends `...[truncated N bytes]`. Keep redaction before the cap.
- **Never log secret material.** No tokens, passwords, private keys, or full request bodies. Do
  not truncate a secret to a "safe prefix" for logging — a prefix of the real secret is still
  live secret material. Use automatic redaction (fields flagged sensitive, or matched by
  `log_field_is_sensitive`, render as `<redacted>` via `redact_log_value`/`redact_log_message`)
  or a purpose-built one-way summary such as `auth::redacted_token_for_log` (`src/auth/token.cpp`),
  which buckets token length into coarse size classes instead of disclosing length or bytes.
- Log the `user_id` and `device_id` (not the token) for authenticated request traces.
- **An audit event that an unauthenticated client can trigger on every request must not write one
  durable row per request.** `access_token.rejected`, `rate_limit.exceeded`, `request.rejected`,
  `login.rejected` and `login.throttled` pass through `AuditRateGate` (10 rows per kind per 60 s, the rest counted and reported as
  `suppressed=<n>` on the next row). A new per-request rejection audit event of that kind must be
  added to `audit_event_is_rate_capped` (ADR-0080). Never gate authenticated or administrative
  events.
- Client-supplied text in an audit `actor`, `target` or `reason` is cut to 255 bytes and
  sanitised (`database::bounded_utf8`) by `append_local_audit` / `append_audit_event`; do not
  write around those two functions.
- Every new log call added to security-sensitive paths must be reviewed in `docs/observability-audit.md`.

## Key doc

- `docs/observability-audit.md` — audit event catalogue and log field schema
