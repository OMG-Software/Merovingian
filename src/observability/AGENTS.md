# src/observability/ — Observability Module

Structured logging and audit trail for the server.

## Key files

| File | Responsibility |
|---|---|
| `observability.cpp` | Audit event types and the audit log sink |
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

Security-relevant events must be emitted as structured audit log entries (not plain log lines):
- Login success / failure (with remote IP)
- Token invalidation
- Rate limit exceeded
- Federation request authenticated / rejected
- Media quarantine triggered

## Rules

- **Never log secret material.** No tokens, passwords, private keys, or full request bodies.
  Truncate to a safe prefix (e.g., first 8 chars of a token) if identity is needed in logs.
- Log the `user_id` and `device_id` (not the token) for authenticated request traces.
- Every new log call added to security-sensitive paths must be reviewed in `docs/observability-audit.md`.

## Key doc

- `docs/observability-audit.md` — audit event catalogue and log field schema
