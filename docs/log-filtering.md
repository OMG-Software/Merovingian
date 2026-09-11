# Operator log filtering

Configured log levels control which diagnostic messages can reach either
output sink. This applies to structured diagnostics, direct `SingleLog`
calls, and the `LOG_*`/`LOGF_*` macros. Audit persistence is independent
of diagnostic filtering.

## `--debug` and the default level

`--debug` lowers the **console sink** threshold to `debug`. It does not
override `log_modules` or change the module default, which is `info`.
A message must meet both its module threshold and its output sink threshold.
An explicit module setting overrides the wildcard default for that module.
`info` suppresses `trace` and `debug`, while retaining `info` and higher
severities, including warnings and errors. `off` suppresses all diagnostic
messages from the selected module.

To suppress debug messages even in a `--debug` run, set:

```conf
# Applies to every module without an explicit override
log_modules.*=info
```

## Silencing a noisy module

`http_server` is the loudest module in steady state — every request
gets a `request.received` line. To silence it while keeping `auth`
verbose:

```conf
log_modules.http_server=info
log_modules.auth=debug
```

Restart the server. The bootstrap runs once at `start_client_server`.

## Bumping a quiet module

To see why a specific 5xx is happening, raise a single module:

```conf
log_modules.client_server=debug
log_modules.rate_limit=debug
```

## Audit-routed failure lines

The following failure events are persisted to `audit_log` independently of
diagnostic filtering — they are audit-routed instead of also emitting a
duplicate diagnostic warning for the same event, not the full catalogue of
durable audit events. See [Observability and audit](observability-audit.md)
("Failure routing" and "Other durably persisted event families") for the
complete picture, including the many success/failure event families
(`auth.*`, `room.*`, `media.*`, etc.) that are always persisted regardless of
severity.

| Logger | Audit event type | Audit category |
|--------|------------------|----------------|
| `rate_limit` | `rate_limit.exceeded` | `policy` |
| `auth` | `login.rejected` | `auth` |
| `auth` | `access_token.rejected` | `auth` |
| `client_server` | `request.rejected` | `policy` |
| `client_server` | `request.user_locked` | `auth` |
| `client_server` | `request.user_suspended` | `auth` |
| `auth` | `registration_policy.denied` | `policy` |
| `federation` | `federation.acl_rejected` | `policy` (in-memory only — see below) |

Federation audit events (`federation.*`, including `federation.acl_rejected`)
are the one exception: `audit_federation()` appends them only to an in-memory
ring (`FederationRuntimeState::audit_events`), never to `audit_log`, so they do
not survive a restart and are not returned by
`GET /_merovingian/admin/audit`. See
[Observability and audit](observability-audit.md#federation-audit-events-are-not-durable).

For a client HTTP 429, `rate_limit.exceeded` emits the warning with the
effective IP and cap details. The additional `request.rejected` audit record
is retained without a second diagnostic warning. Other request rejections
still emit their own warning. Rate-limit enforcement and retry responses
are unaffected by this diagnostic deduplication.

## Reading the audit log

```sh
# All rate-limit hits
curl 'http://127.0.0.1:8008/_merovingian/admin/audit?category=policy&event_type=rate_limit.exceeded'

# All login rejections (no category filter)
curl 'http://127.0.0.1:8008/_merovingian/admin/audit?event_type=login.rejected'

# All policy events
curl 'http://127.0.0.1:8008/_merovingian/admin/audit?category=policy'
```

A malformed `category=` value returns 400 with
`unknown audit category: <name>` so typos fail loud.

## Module names

The `log_modules.<name>` keys accept any string — the bootstrap
forwards the name to `SingleLog::set_module_log_level(name, level)`
without a registry. This is a non-exhaustive list of common module names
used as the first argument to `observability::log_diagnostic` in `src/`:

| Module | What it logs |
|--------|--------------|
| `http_server` | Per-request line and per-request reject |
| `client_server` | Client-server request lifecycle |
| `auth` | Login, session, and access-token decisions |
| `rate_limit` | 429s and engine denials |
| `runtime` | Runtime startup, listener ready, database ready |
| `local_router` | Local HTTP router (audit, health, federation) |
| `federation` | Inbound federation policy/signature/transaction decisions |
| `dispatch_worker` | Federation PDU/EDU dispatch |
| `migration` | Database migration progress |
| `rooms` | Room creation, membership writes, event composition and persistence |
| `event_auth` | Matrix event-auth rule rejection step and reason |
| `persistent_store` | Membership, room-membership, and event/state persistence outcomes |

Unrecognised module names are accepted and the level is recorded —
there is no error. Restart the server to apply.

Legacy `LOG_*`/`LOGF_*` macros use the calling function name as their logger
name (for example, `handle` for the WorkerPool reply diagnostic). They obey
that name's explicit setting, or `log_modules.*` when none exists. Function
traces use `FunctionTrace`. Structured diagnostics use the named modules
in the table above.
