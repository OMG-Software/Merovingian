# Operator log filtering (0.5.0)

The `--debug` flag is the operator's escape hatch when an investigation
needs every line the runtime can produce. It is also a firehose. This
guide covers the 0.5.0 knobs that let you dial the firehose down to
the modules you care about, plus the audit-routing changes that
guarantee the high-signal lines never get lost in the noise.

## `--debug` and the default level

`--debug` lowers the **default** log level to `debug` so modules
without an explicit override start speaking at debug-level verbosity.
Nothing about per-module filtering changes unless you also set
`log_modules.*` keys in `merovingian.conf`.

To revert to the pre-0.5.0 default, drop `--debug` or set the
default level explicitly:

```conf
# Silences everything not explicitly bumped to a higher level
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

The five high-signal failure call sites emit a structured log line
**and** append a row to `audit_log` at the same instant:

| Logger | Audit event type | Audit category |
|--------|------------------|----------------|
| `rate_limit` | `rate_limit.exceeded` | `policy` |
| `auth` | `login.rejected` | `auth` |
| `auth` | `access_token.rejected` | `auth` |
| `client_server` | `request.rejected` | `policy` |
| `auth` | `registration_policy.denied` | `policy` |

`log_diagnostic_audit` is the helper. It is the **only** path that
writes to `audit_log` from these call sites, so a row in the audit
log and a line in stderr will always agree on the actor / target /
reason.

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
without a registry. The runtime uses the following conventions:

| Module | What it logs |
|--------|--------------|
| `http_server` | Per-request line and per-request reject |
| `client_server` | Client-server request lifecycle |
| `auth` | Login, session, and access-token decisions |
| `rate_limit` | 429s and engine denials |
| `runtime` | Runtime startup, listener ready, database ready |
| `local_router` | Local HTTP router (audit, health, federation) |
| `dispatch` | Federation PDU/EDU dispatch |
| `migrate` | Database migration progress |

Unrecognised module names are accepted and the level is recorded —
there is no error. Restart the server to apply.
