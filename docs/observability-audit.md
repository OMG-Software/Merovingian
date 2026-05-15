# Observability and audit

This capability note describes runtime-wired observability and audit behavior.

## Included now

- Admin health summaries through `/_merovingian/admin/health`.
- Admin metrics summaries through `/_merovingian/admin/metrics`.
- Admin audit summaries through `/_merovingian/admin/audit`.
- Structured log redaction helpers.
- Health, metric, and hardening snapshot helpers.
- Durable audit rows for runtime startup, authentication, session, device, key
  API, room, media, federation, and trust-and-safety actions.
- Durable admin action rows for moderation and trust-and-safety review actions.

## Security posture

Runtime metrics and audit summaries are bounded operational summaries. They
report counts, event types, actors, targets, and reason codes, but do not expose
plaintext passwords, bearer tokens, key payloads, media bytes, or event content.

## Deliberately not included

- Prometheus/OpenMetrics scrape contract.
- Distributed tracing and request correlation beyond current request IDs.
- Operator dashboards.
- Retention and export policy for production audit archives.
