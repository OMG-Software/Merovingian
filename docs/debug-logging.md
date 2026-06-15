# Debug Logging

Merovingian emits structured diagnostic log summaries through the existing
`SingleLog` logger. Console output defaults to `info`; pass `--debug` to
`merovingian-server` to show debug diagnostics on the console. Pass
`--log-file <path>` to write trace/debug diagnostics to a file.

Example:

```sh
merovingian-server --debug --log-file /var/log/merovingian/debug.log --config /etc/merovingian/merovingian.conf
```

This starts the server with console debug output and a durable diagnostic log
file for join-failure triage. Low-severity log batches now flush every 1 second
or every 100 messages, whichever comes first, so a quiet debug session does not
wait indefinitely for a severity bump or a large burst of traffic.

## Per-module level overrides (0.5.0)

`--debug` lowers the **default** level to `debug` for every module that
does not have an explicit override. To narrow the firehose to the
modules you care about, set `log_modules.<name>=<level>` keys in
`merovingian.conf`. See `docs/log-filtering.md` for the full recipe and
the list of recognised module names.

## Join Failure Diagnostics

For failed room joins, enable debug/file logging and inspect events with these
logger names:

- `http_server`: request parsing, body limits, dispatch start, response status,
  TLS handshake failures, and listener accept failures.
- `client_server`: Matrix client-server route dispatch, access-token acceptance
  or rejection, `/rooms/{roomId}/join`, and `/join/{roomIdOrAlias}` rewrite
  outcomes. Room identifiers in join diagnostics are decoded from Matrix URL
  path components before lookup, so `%3A` appears as `:` in the room ID.
- `local_router`: internal local route dispatch into room, media, admin, and
  federation handlers.
- `auth`: login and access-token lookup decisions without exposing token values.
- `rooms`: room creation, join membership writes, event composition, signing,
  event authorization, and persistence outcomes.
- `event_auth`: Matrix event-auth rule rejection step and reason.
- `persistent_store`: membership, room-membership, and event/state persistence
  acceptance or rejection.
- `federation`: inbound federation policy/signature/transaction decisions and
  outbound membership transaction composition.

## Redaction Boundary

Diagnostic summaries preserve route, actor, room, status, and reason fields, but
the formatter redacts fields whose names indicate secrets or payloads:

- Authorization headers, access tokens, refresh tokens, sessions, passwords, and
  secrets.
- Signatures and signing material.
- Request bodies, event content, content JSON, media bytes, and E2EE key payload
  maps.
- Query-string values with sensitive token-like names, such as
  `access_token=<redacted>`.

Local HTTP router diagnostics now also include `request_id`, `trace_id`, and
`span_id` fields. These are safe correlation identifiers only: they exist so an
operator can join an admin scrape or audit query to the log lines that handled
it, and they must not be repurposed to carry user payloads or secret material.

Do not add raw request bodies, Matrix event `content`, media bytes, passwords, or
token values to diagnostic fields. Prefer metadata such as `body_bytes`,
`event_type`, `room_id`, `event_id`, `status`, and failure `reason`.
