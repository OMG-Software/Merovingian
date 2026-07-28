# Observability and audit

This capability note describes runtime-wired observability and audit behavior.

## Included now

- Admin health summaries through `/_merovingian/admin/health`.
- Admin metrics summaries through `/_merovingian/admin/metrics`.
- Admin audit summaries through `/_merovingian/admin/audit` (with
  `?category=` and `?event_type=` query-string filters).
- Structured log redaction helpers. `contains_sensitive_marker` (used by
  `sanitize_query`/`sanitized_http_target` to redact query-string values)
  recognizes the bare key `token` as sensitive, in addition to
  `access_token`/`refresh_token`/`session_token` — needed because
  `GET /_matrix/client/v1/register/m.login.registration_token/validity`
  passes the plaintext registration token as `?token=`.
- Stable request-correlation fields (`request_id`, `trace_id`, `span_id`) for
  local HTTP router diagnostics.
- Health, metric, and hardening snapshot helpers.
- Prometheus text exposition for `GET /_merovingian/admin/metrics`.
- Durable audit rows for runtime startup, authentication, session, device, key
  API, room, media, federation, and trust-and-safety actions.
- Durable admin action rows for moderation and trust-and-safety review actions.
- Account-moderation audit rows: `account.locked` and `account.suspended`
  (admin category) are appended when an admin locks/unlocks or
  suspends/unsuspends a user via `/_matrix/client/v1/admin/lock/{userId}` or
  `/_matrix/client/v1/admin/suspend/{userId}`, keyed by admin actor, target
  user, and a `locked`/`unlocked`/`suspended`/`unsuspended` reason code.
- Request-path account-state audit rows: `request.user_locked` and
  `request.user_suspended` (auth category) are appended when an authenticated
  request is rejected because the caller is locked (`M_USER_LOCKED`) or
  suspended (`M_USER_SUSPENDED`), keyed by actor, target path, and reason.
- `auth.password_changed` (auth category) records a password change and notes
  when `logout_devices: true` revoked the user's other device tokens/sessions.
- `federation.edu.direct_to_device.store_incomplete` (warning severity, via
  `log_diagnostic`) fires whenever an inbound `m.direct_to_device` EDU targets
  one or more devices but fewer messages persist to `to_device_messages` than
  were targeted (malformed per-device field, store rejection, or backend write
  failure). Fields: `origin`, `targeted`, `stored` — never the message content
  or ciphertext. Previously this failure mode was silent: the sink always
  returned `EduDispositionStatus::accepted` regardless of what actually
  persisted, so a lost megolm room-key share left no trace anywhere in the
  logs (issue #464).
- `federation.acl_rejected` (warning severity, via `audit_federation`) fires
  when an inbound federation request, PDU, or room-local EDU is denied by the
  room's `m.room.server_acl` (MSC4436). Diagnostic companions `pdu.acl_rejected`
  and `edu.acl_rejected` carry `origin`, `room_id`, `event_id`/`edu_type`, and
  `reason` so operators can trace why a server was blocked without exposing
  key material.

## Failure routing (0.5.0)

Five high-signal failure call sites route through a single
`observability::log_diagnostic_audit` helper. At severity `warning` or
above, the helper both emits the structured log line and appends a row
to `audit_log`:

| Call site | Logger | Audit category | Audit event type |
|-----------|--------|----------------|------------------|
| Rate-limit 429 | `rate_limit` | `policy` | `rate_limit.exceeded` |
| Login rejected | `auth` | `auth` | `login.rejected` |
| Access-token rejected | `auth` | `auth` | `access_token.rejected` |
| Client-server request rejected | `client_server` | `policy` | `request.rejected` |
| Locked-user request rejected | `client_server` | `auth` | `request.user_locked` |
| Suspended-user request rejected | `client_server` | `auth` | `request.user_suspended` |
| Registration policy denied | `auth` | `policy` | `registration_policy.denied` |
| Federation ACL rejected | `federation` | `federation` | `federation.acl_rejected` |

The `access_token.rejected` row carries a `reason` that distinguishes the
failure mode: `token hashing failed`, `session not found`, `user not found`,
and — for an expired-but-not-revoked token (#275) — `token expired`. The
expired reason is emitted only when a session matching the token hash exists,
is not revoked, but is past its `expires_at`, so operators can tell a stale
TTL from a genuinely unknown token.

The audit row is keyed by the same actor / target / reason that
appears in the structured log line, so an operator can pivot from
`stderr` to `audit_log` without re-parsing. The log side and the
audit row are emitted from the same call site to keep them in lockstep.

**Audit sink installation on worker threads (issue #420):** the active
`LocalDatabase*` the sink writes through is a `thread_local`
(`homeserver/local_services.cpp`), installed by `LocalDatabaseScope` only on
the thread that constructs `HomeserverRuntime` (main). Every call site above
that routes through the sink-based `observability::log_diagnostic_audit`
overload (rather than the explicit-database overload) previously silently
no-op'd when it ran on an HTTP `ThreadPool` worker thread — in practice this
meant `registration_policy.denied` was never recorded in production, since
`/register` is dispatched on a pool worker. `net::ThreadPool` gained an
`on_thread_start` hook; `main.cpp`'s `serve_until_shutdown` passes a callback
that installs the audit database on every worker thread in both the main
and sync HTTP pools before they start dequeuing work.

### Operator recipe

```sh
# All rate-limit hits in the last 24h, by category
curl 'http://127.0.0.1:8008/_merovingian/admin/audit?category=policy&event_type=rate_limit.exceeded'

# All login rejections for a specific user (filter by event_type only)
curl 'http://127.0.0.1:8008/_merovingian/admin/audit?event_type=login.rejected'

# All audit rows
curl 'http://127.0.0.1:8008/_merovingian/admin/audit'
```

A malformed `category=` value returns 400 with a clear
`unknown audit category: <name>` error rather than silently dropping
the request. Unknown `event_type=` values are treated as a no-match
filter; the response is empty (still 200).

## Security posture

Runtime metrics and audit summaries are bounded operational summaries. They
report counts, event types, actors, targets, and reason codes, but do not expose
plaintext passwords, bearer tokens, key payloads, media bytes, or event content.

The opt-in client_server event=sliding_sync.debug_response diagnostic is
available only when the process starts with --debug; it is not an audit event
and is never persisted. Its connection identifier data is limited to presence
and byte length, and it contains no request bodies, tokens, event content, or
encryption material.

## Scrape/export contract

`GET /_merovingian/admin/metrics` is the stable scrape endpoint for operators.
It returns `200 OK` with `Content-Type: text/plain; version=0.0.4; charset=utf-8`
and two correlation headers:

- `X-Merovingian-Request-Id: req-...`
- `Traceparent: 00-<trace_id>-<span_id>-01`

The body uses Prometheus text exposition with stable `# HELP` and `# TYPE`
metadata ahead of each metric family. Core families currently exported are:

- `merovingian_server_identity{server_name="..."} 1`
- `merovingian_runtime_started`
- `merovingian_database_schema_version`
- `users_total`
- `sessions_total`
- `rooms_total`
- `events_total`
- `audit_events_appended_total`
- `admin_actions_total`
- `merovingian_health_status{component="...",status="ok|degraded|failed"}`
- all `media_*` repository counters and gauges already tracked by the runtime

Metric names and label keys are ASCII-safe, payload-free operator fields. New
families must carry a `# HELP` line, a `# TYPE` line, and must not encode secret
material in either names or label values.

## Trace correlation contract

Structured diagnostics for local HTTP router request handling now carry these
fields in the log line itself:

- `request_id=req-...`
- `trace_id=<32 lowercase hex chars>`
- `span_id=<16 lowercase hex chars>`

The contract is intentionally narrow: the correlation identifiers exist to join
an operator's scrape or admin query to the structured request diagnostics that
served it. They are not a distributed tracing system and are not yet persisted
into the durable audit rows.

## Deliberately not included

- Distributed tracing beyond the local request-correlation contract above.
- Operator dashboards.
- Retention and export policy for production audit archives.
