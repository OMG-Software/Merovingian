# Debug Logging

Merovingian emits structured diagnostic log summaries through the existing
`SingleLog` logger. Console output defaults to `info`; pass `--debug` to
`merovingian-server` to show debug diagnostics on the console. Pass
`--log-file <path>` to write trace/debug diagnostics to a file. The file is
opened without following a symlink, made `0600`, and truncated at start-up; a
path that is not a regular file the server owns is refused (ADR-0146).

Example:

```sh
merovingian-server --debug --log-file /var/log/merovingian/debug.log --config /etc/merovingian/merovingian.conf
```

This starts the server with console debug output and a durable diagnostic log
file for join-failure triage. Low-severity log batches now flush every 1 second
or every 100 messages, whichever comes first, so a quiet debug session does not
wait indefinitely for a severity bump or a large burst of traffic.

## Push overload diagnostics

`push.delivery.dropped` is a warning, not debug-only. `scope=global` or
`scope=recipient` identifies the exhausted budget; numeric `in_flight`, `cap` and
`deliveries` describe that budget and the dropped recipient batch.
`scope=allocation` or `scope=admission` reports resource/launch failure with global
budget counts. The record excludes recipient identities, gateway URLs and pusher
credentials. Logging failure does not fail the already-persisted event.

## Room creation failures

`room.create.failed` (module `rooms`) is an error, not debug-only. It is
written once whenever `create_room` answers a 5xx, for `createRoom`, `/upgrade`
and the local router alike, with `actor`, `room_id` (empty if the failure came
before the room ID was derived), `status` and `reason`. A refusal the client
caused (401, 400, 403) stays a debug-level `room.create.rejected`. Before 0.12.27 a failed creation was logged
only at debug, so a 500 left nothing in a default log. `room.create.room_id_taken`
(debug) records each timestamp `create_room` stepped past because its room v12 ID
already existed (ADR-0156).

## Sliding Sync response diagnostics (0.10.41)

Starting the server with --debug additionally enables the
client_server event=sliding_sync.debug_response record. This record is
unavailable on a normal startup, even if configuration raises the
client_server module's log level.

It records only diagnostic metadata: whether the client used a connection ID
(and its byte length), the requested and returned positions, request list and
subscription counts, per-connection cursors, list-operation count, enabled
extension names, room counts, and response byte count. It never records the
connection ID itself, request bodies, access tokens, event content, or
encryption material.

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

Every diagnostic field value is also length-capped: a value whose escaped form
exceeds 2048 bytes is cut on a character boundary and followed by
`...[truncated N bytes]`, so a client-supplied identifier cannot inflate a log
line (see `docs/observability-audit.md`).

Do not add raw request bodies, Matrix event `content`, media bytes, passwords, or
token values to diagnostic fields. Prefer metadata such as `body_bytes`,
`event_type`, `room_id`, `event_id`, `status`, and failure `reason`.
