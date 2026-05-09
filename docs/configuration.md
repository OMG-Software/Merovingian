# Configuration

The Phase 1 bootstrap configuration uses a conservative dependency-free `key=value` format.

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

Startup rejects configuration before doing runtime work when parser or validation findings are present.

Rejected cases include:

- unreadable config path
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
- invalid media upload size
- disabled private-IP blocking for remote media fetches
- disabled sandboxed media decoding
- disabled token or event-content log redaction

## Exit codes

Bootstrap exits with explicit status codes:

| Code | Meaning |
| ---: | --- |
| 0 | Success, help, or version output |
| 64 | Usage error |
| 66 | Config file open/read failure |
| 78 | Config parse failure |
| 79 | Config validation failure |

## Listener exposure policy

The Phase 1 defaults bind both client and federation listeners to loopback with TLS disabled. This supports a reverse-proxy deployment model while avoiding accidental public cleartext exposure.

A listener with `tls=false` must bind to one of:

- `127.0.0.1`
- `localhost`
- `::1`
- `[::1]`

A non-loopback listener must set `tls=true`.

## Media size format

`security.media.max_upload_size` accepts positive bounded byte sizes with one of these suffixes:

- `B`
- `KiB`
- `MiB`
- `GiB`

Examples:

```text
security.media.max_upload_size=50MiB
security.media.max_upload_size=1048576B
```

Values such as `0MiB`, `50MB`, `-1MiB`, `50 MiB`, and `unbounded` are rejected.

## Current keys

See `config/merovingian.conf.example` for the complete accepted Phase 1 key list.
