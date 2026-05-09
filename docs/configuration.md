# Configuration

The bootstrap configuration uses a conservative dependency-free `key=value` format.

This format is intentionally narrow while the runtime is still being built. It provides a checked operator-facing configuration path without adding a YAML, TOML, or JSON dependency before dependency review is complete.

## Example

Use the checked-in starter config:

```bash
./build/src/merovingian-server --config config/merovingian.conf.example
```

Running without `--config` uses the same secure typed defaults compiled into the server.

```bash
./build/src/merovingian-server
```

Validate a configuration file without starting runtime scaffolding:

```bash
./build/src/merovingian-server --check-config config/merovingian.conf.example
```

## Format rules

- One `key=value` pair per line.
- Blank lines are ignored.
- Lines beginning with `#` are ignored.
- Whitespace around keys and values is trimmed.
- Boolean values must be exactly `true` or `false`.
- Unsigned integers must contain digits only.
- Lists are comma-separated.
- Duplicate keys are rejected.
- Unknown keys are rejected.
- Malformed lines are rejected.
- Files larger than 1 MiB are rejected.
- Lines longer than 4 KiB are rejected.
- Parsed configuration is always validated before startup continues.

## Fail-closed startup

Startup rejects configuration before doing runtime work when parser or validation findings are present. `--check-config <path>` runs the same file metadata, parser, validation, and existing secret-file permission checks, but exits before startup runtime summary or listener/database/federation scaffolding.

Rejected cases include:

- unreadable config path
- missing config path
- unsafe config file permissions
- unsafe existing secret file permissions
- oversized config file
- oversized config line
- duplicate config key
- unknown config key
- malformed line
- invalid boolean value
- invalid unsigned integer value
- empty required server/listener/database values
- non-HTTPS public base URL
- malformed listener bind address
- cleartext listener on a non-loopback interface
- open registration without token requirement
- disabled default encryption for new rooms
- disabled direct-message encryption requirement
- invalid federation default policy
- disabled federation TLS validation
- disabled federation JSON signature verification
- missing private or loopback federation deny ranges
- invalid federation transaction size
- invalid federation remote timeout
- invalid media upload size
- disabled private-IP blocking for remote media fetches
- disabled sandboxed media decoding
- disabled token or event-content log redaction

## Exit codes

Bootstrap exits with explicit status codes:

| Code | Meaning |
| ---: | --- |
| 0 | Success, help, version output, or successful config check |
| 64 | Usage error |
| 66 | Config file open/read failure |
| 78 | Config parse failure |
| 79 | Config validation failure |

## Listener exposure policy

The defaults bind both client and federation listeners to loopback with TLS disabled. This supports a reverse-proxy deployment model while avoiding accidental public cleartext exposure.

A listener with `tls=false` must bind to one of:

- `127.0.0.1`
- `localhost`
- `::1`
- `[::1]`

A non-loopback listener must set `tls=true`.

## Size and duration formats

Size values accept positive bounded byte sizes with one of these suffixes:

- `B`
- `KiB`
- `MiB`
- `GiB`

Examples:

```text
security.media.max_upload_size=50MiB
security.federation.max_transaction_size=10MiB
```

Values such as `0MiB`, `50MB`, `-1MiB`, `50 MiB`, and `unbounded` are rejected.

Duration values accept positive bounded durations with one of these suffixes:

- `s`
- `m`

Examples:

```text
security.federation.remote_timeout=30s
security.federation.remote_timeout=1m
```

Values such as `0s`, `30`, `30ms`, and `forever` are rejected.

## Reloadability policy

Configuration parsing and validation are restart-safe today. Runtime hot reload is a Phase 2 boundary, not a completed control plane. The server now classifies keys by reload policy so later SIGHUP or admin-socket reload work can apply reloadable settings without treating every config change as a whole homeserver restart.

Reload planning compares validated current and next configs and reports how many changes are reloadable versus restart-required. Planning is analysis-only until the live reload control path exists.

| Key or key group | Policy |
| --- | --- |
| `server.name` | Restart required |
| `database.uri_file` | Restart required |
| `database.pool_size` | Reloadable |
| `listeners.*` | Reloadable |
| `security.registration.*` | Reloadable |
| `security.encryption.*` | Reloadable |
| `security.federation.*` | Reloadable |
| `security.media.*` | Reloadable |
| `security.logging.*` | Reloadable |

Restart-required keys affect stable process identity or secret source selection. Reloadable keys are runtime policy or limit values that should be applied through the future reload path without a full homeserver restart.

## Current keys

See `config/merovingian.conf.example` for the complete accepted key list.
