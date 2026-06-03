# Observability and audit

This capability note describes runtime-wired observability and audit behavior.

## Included now

- Admin health summaries through `/_merovingian/admin/health`.
- Admin metrics summaries through `/_merovingian/admin/metrics`.
- Admin audit summaries through `/_merovingian/admin/audit` (with
  `?category=` and `?event_type=` query-string filters).
- Structured log redaction helpers.
- Health, metric, and hardening snapshot helpers.
- Durable audit rows for runtime startup, authentication, session, device, key
  API, room, media, federation, and trust-and-safety actions.
- Durable admin action rows for moderation and trust-and-safety review actions.

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
| Registration policy denied | `auth` | `policy` | `registration_policy.denied` |

The audit row is keyed by the same actor / target / reason that
appears in the structured log line, so an operator can pivot from
`stderr` to `audit_log` without re-parsing. The log side and the
audit row are emitted from the same call site to keep them in lockstep.

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

## Deliberately not included

- Prometheus/OpenMetrics scrape contract.
- Distributed tracing and request correlation beyond current request IDs.
- Operator dashboards.
- Retention and export policy for production audit archives.
