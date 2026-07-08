# Merovingian User Manual

This manual covers installing, configuring, running, and operating The
Merovingian Matrix homeserver. It is written for server administrators and
assumes basic familiarity with POSIX systems, networking, and the Matrix
protocol.

> **Beta status.** Merovingian is suitable for evaluation and testing. It is not
> yet production-ready. Do not deploy it as a production Matrix homeserver until
> the blocking items in
> [`docs/todos/production-milestone.md`](todos/production-milestone.md) are
> closed.

For developer-oriented documentation — build internals, testing conventions, and
contribution rules — see [`docs/dev-environment.md`](dev-environment.md) and the
other docs linked from [`README.md`](../README.md).

## Table of contents

- [What Merovingian is](#what-merovingian-is)
- [System requirements](#system-requirements)
- [Installation](#installation)
- [Initial setup](#initial-setup)
- [Configuration](#configuration)
- [Database backends](#database-backends)
- [Running the server](#running-the-server)
- [Reverse proxy](#reverse-proxy)
- [User management](#user-management)
- [Federation](#federation)
- [Media repository](#media-repository)
- [Logging and diagnostics](#logging-and-diagnostics)
- [Maintenance](#maintenance)
- [Troubleshooting](#troubleshooting)
- [Security checklist](#security-checklist)

## What Merovingian is

Merovingian is a Matrix homeserver written in C++26 with a security-first
design. It treats secure defaults, fail-closed validation, narrow trust
boundaries, and operational visibility as primary requirements rather than
later hardening passes.

Key design choices that affect operators:

- **Reverse-proxy-first deployment.** Client and federation listeners default to
  loopback (`127.0.0.1:8008` and `127.0.0.1:8009`) with TLS disabled. A reverse
  proxy owns public TLS and routes traffic to the loopback listeners.
- **Fail-closed configuration.** Startup rejects unsafe or ambiguous settings
  before binding listeners, scaffolding the database, or launching federation
  workers.
- **Out-of-process federation worker.** When federation is enabled (the default),
  all inbound federation traffic is handled by one or more separate
  `merovingian-fed-worker` child processes that communicate with the main
  process over an encrypted AF_UNIX channel.
- **Redaction-aware logs.** Diagnostic logs and the audit log intentionally omit
  tokens, secrets, event content, and media bytes.

## System requirements

Merovingian targets POSIX server platforms. See
[`docs/platform-support.md`](platform-support.md) for the full support-tier
matrix.

### Build toolchain (for source builds)

- **Clang ≥ 18** or **GCC ≥ 14** with a matching C++26 standard library
- **Meson ≥ 1.1.0** and Ninja
- POSIX shell, Python (for `build.py`), Perl, Bison, Flex, M4

### Runtime dependencies

These are resolved from the operating-system package manager and receive normal
OS security updates:

- OpenSSL
- LibSodium
- PostgreSQL libpq
- libcurl
- libpng / libjpeg-turbo (media)

SQLite, yyjson, and Catch2 are vendored as Meson subprojects and built from
source-pinned wraps.

### Minimum platform versions

| Platform | Minimum version |
|---|---|
| Ubuntu | 24.04 LTS |
| Debian | 13 (trixie) |
| Fedora | 40+ |
| RHEL-compatible | RHEL 10 / AlmaLinux 10 |
| OpenSUSE | Tumbleweed |
| FreeBSD | 14.1+ |
| OpenBSD | 7.6+ with the `llvm` package |
| NetBSD | 10+ with pkgsrc `clang` |

Older Linux distributions cannot run a glibc-dynamic build linked against newer
libraries. Use the portable static Linux tarball (musl) for those hosts.

### Resource guidance

- **Small evaluation / single-user:** 1 vCPU, 1 GiB RAM, SQLite backend.
- **Small federation-enabled server:** 2 vCPUs, 2 GiB RAM, PostgreSQL backend.
- **Large federated rooms:** Federation joins to rooms with tens of thousands of
  members need extra RAM and a higher `security.federation.join_timeout` budget
  (see [Federation](#federation)).

## Installation

### Install from a distro package (recommended)

Tier 1 and Tier 2 CI produces `.deb`, `.rpm`, `.pkg`, and `.tgz` packages for
Ubuntu, Debian, Fedora, RHEL/AlmaLinux, OpenSUSE, FreeBSD, OpenBSD, and NetBSD.
The rolling `latest` GitHub prerelease is rebuilt on every push to `main`.

```sh
# Debian/Ubuntu example
dpkg -i merovingian_0.10.33_amd64.deb

# Fedora/RHEL example
dnf install merovingian-0.10.33-1.fc40.x86_64.rpm
```

Packages create the `merovingian` system user and group, install the systemd
unit, and stage the example configuration at `/etc/merovingian/
merovingian.conf.example`.

### Install the portable static Linux tarball

For older Linux distributions, use the musl-linked tarball. It has no glibc or
runtime package dependencies.

```sh
tar xzf merovingian-0.10.33-linux-static-x86_64.tar.gz
cp merovingian-0.10.33-linux-static-x86_64/bin/merovingian-server /usr/local/bin/
cp merovingian-0.10.33-linux-static-x86_64/bin/merovingian-db-migrate /usr/local/bin/
cp merovingian-0.10.33-linux-static-x86_64/libexec/merovingian/merovingian-fed-worker \
   /usr/local/libexec/merovingian/
```

The static tarball does **not** receive automatic dependency security updates;
redeploy a new tarball to pick up OpenSSL/LibSodium/libcurl fixes.

### Build from source

The unified build script configures, compiles, and tests in one step:

```sh
sh scripts/setup-dev-env.sh      # install toolchain and configure build dir
python build.py linux             # or `python build.py wsl` on Windows
```

After a successful build, the binaries are at:

- `build/src/merovingian-server`
- `build/src/merovingian-db-migrate`
- `build/src/federation_worker/merovingian-fed-worker`

For detailed platform-specific instructions, sanitizer builds, and packaging
commands, see [`docs/dev-environment.md`](dev-environment.md).

### Directory layout after installation

| Path | Purpose |
|---|---|
| `/etc/merovingian/` | Configuration files and secret files (master key, DB URI, registration token). |
| `/var/lib/merovingian/` | Database files (SQLite), runtime state, and federation queues. |
| `/var/log/merovingian/` | Diagnostic log files when `--log-file` is used. |
| `/usr/libexec/merovingian/` | Helper binaries (`merovingian-fed-worker`, thumbnail worker). |
| `/usr/bin/` | User-facing binaries (`merovingian-server`, `merovingian-db-migrate`). |

## Initial setup

### 1. Create the service user

Distro packages create this automatically. For a manual or static install:

```sh
groupadd -r merovingian
useradd -r -g merovingian -d /var/lib/merovingian \
        -s /sbin/nologin -c "Merovingian homeserver" merovingian
install -d -o merovingian -g merovingian -m 0750 /var/lib/merovingian
install -d -o merovingian -g merovingian -m 0750 /var/log/merovingian
```

### 2. Copy and edit the example configuration

```sh
install -d -m 0755 /etc/merovingian
install -m 0644 config/merovingian.conf.example /etc/merovingian/merovingian.conf
```

The three values that must match your deployment are:

```ini
server.name=example.org
server.public_baseurl=https://matrix.example.org
server.trusted_proxies=127.0.0.1
```

### 3. Generate the master key

The master key encrypts the Ed25519 signing secret before it is stored in the
database. Generate 32 random bytes and protect the file:

```sh
openssl rand -out /etc/merovingian/master-key 32
chmod 0600 /etc/merovingian/master-key
chown merovingian:merovingian /etc/merovingian/master-key
```

Without a master key, fresh signing keys cannot be created; the server can only
load legacy plaintext keys for migration.

### 4. Configure the database

See [Database backends](#database-backends). For a quick evaluation, switch to
SQLite by uncommenting the SQLite block and commenting out the PostgreSQL keys.

### 5. Validate the configuration

```sh
merovingian-server --check-config /etc/merovingian/merovingian.conf
```

A clean validation exits with status `0`. A rejected key, unsafe permission,
or missing secret produces a clear message and a non-zero exit code.

### 6. Create the first admin account

```sh
openssl rand -base64 24 > /tmp/admin-pw
chmod 600 /tmp/admin-pw
merovingian-server --config /etc/merovingian/merovingian.conf \
  --bootstrap-admin alice \
  --bootstrap-admin-password-file /tmp/admin-pw
rm /tmp/admin-pw
```

This creates `@alice:<server.name>` with admin privileges and exits. Public
registration never grants admin privileges.

## Configuration

The bootstrap configuration uses a simple `key=value` format. Full-line comments
start with `#`; inline trailing comments are not supported.

### Format rules

- One `key=value` pair per line.
- Blank lines are ignored.
- Lines beginning with `#` are ignored.
- Whitespace around keys and values is trimmed.
- Booleans must be exactly `true` or `false`.
- Unsigned integers contain digits only.
- Lists are comma-separated.
- Duplicate keys, unknown keys, and malformed lines are rejected.
- Files larger than 1 MiB or lines longer than 4 KiB are rejected.

### Configuration validation modes

```sh
# Validate without starting the server
merovingian-server --check-config /etc/merovingian/merovingian.conf

# Validate and print the startup summary, but do not bind listeners
merovingian-server --dry-run --config /etc/merovingian/merovingian.conf

# Plan whether a reload can be applied without a restart
merovingian-server --plan-config-reload current.conf next.conf
```

### Bootstrap exit codes

| Code | Meaning |
| ---: | --- |
| `0` | Success, help, version, successful config check, or successful reload plan |
| `64` | Usage error |
| `66` | Config file open/read failure |
| `78` | Config parse failure |
| `79` | Config validation failure |

### Configuration parameter reference

The complete, authoritative accepted-key list lives in
[`config/merovingian.conf.example`](../config/merovingian.conf.example). The
following sections describe each group and the situations in which you might
change them.

#### Server identity — `server.*`

| Key | Default | When to change |
|---|---|---|
| `server.name` | `matrix.example.org` | **Required.** The Matrix server name used in user IDs and federation. Must match the host part served by your reverse proxy. |
| `server.public_baseurl` | `https://matrix.example.org` | **Required.** The HTTPS URL clients use. Must be HTTPS. |
| `server.trusted_proxies` | `127.0.0.1` | **Required behind a reverse proxy.** Comma-separated list of proxy IPs whose `X-Forwarded-For` header is trusted for rate limiting. Without this, every client shares one per-IP bucket. |

#### CORS policy — `server.cors.*`

| Key | Default | When to change |
|---|---|---|
| `server.cors.allowed_origins` | `*` | Change to an explicit origin list only when embedding web clients in a mixed-trust context. |
| `server.cors.allow_methods` | `GET, POST, PUT, DELETE, OPTIONS` | Change if you add non-standard client methods. |
| `server.cors.allow_headers` | `authorization, content-type` | Usually sufficient for Matrix clients. |
| `server.cors.allow_credentials` | `false` | Set `true` only with an explicit origin list; `*` plus `true` is rejected by the parser. |
| `server.cors.max_age` | `86400` | Preflight cache lifetime in seconds. |

> Your reverse proxy must **not** emit `Access-Control-Allow-*` headers for
> `/_matrix/` traffic. Merovingian emits them itself; duplicate values cause
> browser clients to fail with CORS errors.

#### Listeners — `listeners.client.*` and `listeners.federation.*`

| Key | Default | When to change |
|---|---|---|
| `listeners.client.bind` | `127.0.0.1:8008` | Client-server API and media. |
| `listeners.client.tls` | `false` | Set `true` only if binding to a public interface without a reverse proxy. |
| `listeners.client.tls_certificate_file` | (empty) | Required when `tls=true`. |
| `listeners.client.tls_private_key_file` | (empty) | Required when `tls=true`. |
| `listeners.federation.bind` | `127.0.0.1:8009` | Federation and key API. Must be separate from the client listener. |
| `listeners.federation.tls` | `false` | Set `true` only for direct public federation without a proxy. |
| `listeners.federation.tls_certificate_file` | (empty) | Required when federation TLS is enabled. |
| `listeners.federation.tls_private_key_file` | (empty) | Required when federation TLS is enabled. |

A listener with `tls=false` must bind to a loopback address (`127.0.0.1`,
`localhost`, `::1`, or `[::1]`). A non-loopback listener must use TLS.

#### Database — `database.*`

| Key | Default | When to change |
|---|---|---|
| `database.backend` | `postgresql` | Set to `sqlite` for development/evaluation. Only one backend line is allowed. |
| `database.uri_file` | `/etc/merovingian/db-uri` | Path to an owner-only file containing the PostgreSQL URI. |
| `database.role` | `runtime` | Use `migration` only with `merovingian-db-migrate`. |
| `database.pool_size` | `16` | Tune based on workload; reloadable. |
| `database.sqlite_path` | (commented out) | Path for SQLite single-file store. |

#### Registration — `security.registration.*`

| Key | Default | When to change |
|---|---|---|
| `security.registration.enabled` | `false` | Set `true` to allow public self-registration. |
| `security.registration.require_token` | `true` | Set `false` only on private test servers; open public registration without a token is rejected by the parser unless explicitly allowed. |
| `security.registration.token_file` | `/etc/merovingian/registration-token` | Owner-only file containing the registration token. |

#### Encryption policy — `security.encryption.*`

These keys enforce the room encryption policy. The defaults require encryption
for direct messages and private rooms and block unencrypted federated private
rooms.

| Key | Default | When to change |
|---|---|---|
| `security.encryption.default_for_new_rooms` | `true` | Disable only in constrained test environments. |
| `security.encryption.require_for_direct_messages` | `true` | Should stay `true` in production. |
| `security.encryption.require_for_private_rooms` | `true` | Should stay `true` in production. |
| `security.encryption.allow_unencrypted_public_rooms` | `true` | Set `false` to require encryption even for public rooms. |
| `security.encryption.block_unencrypted_federated_private_rooms` | `true` | Keep `true` to prevent E2EE bypass across federation. |

#### Token lifetimes — `security.*_token_lifetime_ms`

| Key | Default | When to change |
|---|---|---|
| `security.access_token_lifetime_ms` | `3600000` | Access-token expiry in milliseconds (`0` disables expiry). |
| `security.refresh_token_lifetime_ms` | `2592000000` | Refresh-token expiry in milliseconds (`0` disables expiry). |

#### Federation policy — `security.federation.*`

| Key | Default | When to change |
|---|---|---|
| `security.federation.enabled` | `true` | Set `false` to run a non-federating server. |
| `security.federation.default_policy` | `allow` | Set `deny` for allow-list federation. Requires `allowed_servers`. |
| `security.federation.allowed_servers` | (empty) | Comma-separated server names allowed when `default_policy=deny`. |
| `security.federation.denied_servers` | (empty) | Comma-separated server names always blocked. |
| `security.federation.require_valid_tls` | `true` | Disable only in controlled test labs. |
| `security.federation.verify_json_signatures` | `true` | Disable only in controlled test labs. |
| `security.federation.deny_ip_ranges` | private/loopback ranges | Ranges blocked during remote discovery/fetching. Keep the defaults. |
| `security.federation.remote_timeout` | `60s` | General outbound federation HTTP timeout. |
| `security.federation.max_transaction_size` | `20MiB` | Cap on inbound transaction body size. |

#### Federation join/leave budget — `security.federation.join_*`

| Key | Default | When to change |
|---|---|---|
| `security.federation.join_timeout` | `180s` | Budget for `make_join`/`send_join`/`make_leave`/`send_leave`. |
| `security.federation.join_parallelism` | `8` | Concurrent `make_join` candidate probes. |
| `security.federation.join_race_deadline` | `45s` | Overall wall-clock budget for the whole candidate race. |
| `security.federation.join_max_candidates` | `20` | Hard cap on `via` candidates raced. |
| `security.federation.join_state_key_parallelism` | `100` | Concurrent remote signing-key resolutions while verifying `send_join` state. |
| `security.federation.join_response_max_size` | `64MiB` | Response body cap specifically for `make_join`/`send_join`. **Requires restart.** |

#### Federation inbound abuse controls — `security.federation.*`

| Key | Default | When to change |
|---|---|---|
| `security.federation.max_transaction_pdus` | `50` | Hard cap on PDUs per inbound `/send` transaction. Maximum `50` per Matrix v1.18. |
| `security.federation.max_transaction_edus` | `100` | Hard cap on EDUs per inbound `/send` transaction. Maximum `100` per Matrix v1.18. |
| `security.federation.per_origin_transaction_rate` | `120/60s` | Per-origin `/send` transaction rate. |
| `security.federation.per_origin_pdu_rate` | `600/60s` | Per-origin weighted PDU budget. |
| `security.federation.per_origin_edu_rate` | `1200/60s` | Per-origin weighted EDU budget. |

#### Federation worker — `federation.worker.*`

The federation worker is mandatory when federation is enabled.

| Key | Default | When to change |
|---|---|---|
| `federation.worker.threads` | `4` | Thread pool for endpoints answered from the worker's own snapshot. |
| `federation.worker.relay_threads` | `32` | Thread pool for endpoints that block on main or outbound HTTP. |
| `federation.worker.request_timeout_seconds` | `30` | Per-request IPC timeout. |
| `federation.worker.shards` | `2` | Number of independent worker processes. Room-scoped requests are sharded by `room_id`. |
| `federation.worker.apply_hardening` | `true` | Apply seccomp/capability sandboxing to workers. Keep `true` in production. |
| `federation.worker.binary` | (empty) | Absolute path to `merovingian-fed-worker`; empty uses the compile-time libexec path. |

#### Media repository — `security.media.*`

| Key | Default | When to change |
|---|---|---|
| `security.media.max_upload_size` | `50MiB` | Maximum local upload size. Match your reverse-proxy body-size limit. |
| `security.media.allowed_mime_types` | built-in list | Comma-separated allow-list; keep `application/octet-stream` so encrypted-room attachments are accepted. |
| `security.media.quarantine_unknown_mime` | `true` | Quarantine uploads whose MIME type is not in the allow-list. |
| `security.media.block_private_ip_fetches` | `true` | Block private/loopback origins when fetching remote media. |
| `security.media.remote_fetch_enabled` | `false` | Opt-in for live remote media fetching. |
| `security.media.remote_fetch_timeout` | `30s` | Parsed and validated, but the live path still uses hard-coded timeouts. |
| `security.media.decode_in_sandbox` | `true` | Decode/thumbnail media inside a sandboxed child process. |
| `security.media.local_upload_policy` | `allow-after-scan` | `allow`/`allow-after-scan`/`quarantine`/`deny`. |
| `security.media.remote_fetch_media_policy` | `quarantine` | Same values; defaults to `quarantine` because federated origins are unaccountable. |

> **Encrypted-room media can never be scanned.** Matrix E2EE attachments are
> encrypted client-side before upload. The server only stores opaque
> `application/octet-stream` ciphertext and never holds the decryption key.

#### Trust and safety — `security.trust_safety.*`

| Key | Default | When to change |
|---|---|---|
| `security.trust_safety.enabled` | `false` | Set `true` to consult a remote policy service for registration, room creation, inbound federation, and media downloads. |
| `security.trust_safety.policy_server_url` | (empty) | HTTPS URL of the policy service. Required when enabled. |
| `security.trust_safety.policy_server_timeout` | `5s` | Policy request timeout. |
| `security.trust_safety.policy_server_allow_without_result` | `false` | Set `true` to allow the guarded workflow when the policy service is unreachable. Defaults fail-closed. |

#### Logging redaction — `security.logging.*`

| Key | Default | When to change |
|---|---|---|
| `security.logging.redact_tokens` | `true` | Keep `true` so tokens do not leak into logs. |
| `security.logging.redact_event_content` | `true` | Keep `true` so message content does not leak into logs. |
| `security.logging.structured` | `true` | Structured log format. |

#### At-rest secret protection — `security.secrets.*`

| Key | Default | When to change |
|---|---|---|
| `security.secrets.master_key_file` | `/etc/merovingian/master-key` | Path to the 32-byte master key file. |

#### Client rate limits — `client_rate_limits.*`

| Key | Default | When to change |
|---|---|---|
| `client_rate_limits.per_ip.<target>` | unset | Per-IP cap for requests matching `<target>` prefix. |
| `client_rate_limits.per_user.<target>` | unset | Per-user cap keyed by access token. |
| `client_rate_limits.default_per_ip` | `90/60s` | Fallback cap for unmatched targets. |

The target keys contain literal forward slashes, e.g.:

```ini
client_rate_limits.per_ip./_matrix/client/v3/login=30/60s
client_rate_limits.per_user./_matrix/client/v3/login=20/60s
```

Rate-limit changes require a server restart.

#### Per-module log levels — `log_modules.*`

| Key | Default | When to change |
|---|---|---|
| `log_modules.<module>` | unset | Override the level for a specific module. |
| `log_modules.*` | unset | Set the default level for all unlisted modules. |

Use `log_modules.*=debug` to make a `--debug` run less noisy by default, then
raise or lower specific modules. See [`docs/log-filtering.md`](log-filtering.md)
for the module list.

### Reloadability policy

Configuration keys are classified as **reloadable** or **restart-required**.
The runtime config snapshot can apply reloadable changes without a full server
restart, but the live reload control path (SIGHUP/admin socket) is not yet
wired. Changing any of these currently requires a restart:

- `server.name`
- `database.uri_file`
- `database.role`
- `listeners.*.tls_certificate_file`
- `listeners.*.tls_private_key_file`
- `security.federation.join_response_max_size`
- `federation.worker.*`
- `server.cors.*`
- `client_rate_limits.*`
- `log_modules.*`

Everything else listed above is reloadable in principle; the future reload path
will apply them without restart.

## Database backends

### SQLite (development and evaluation)

SQLite is a single-file store with no separate server process. It is not
recommended for production because it lacks connection pooling, concurrent
write scaling, and role separation.

```ini
database.backend=sqlite
database.sqlite_path=/var/lib/merovingian/merovingian.sqlite3
```

Remove or comment out the PostgreSQL keys when switching to SQLite. Only one
`database.backend` line may be active.

### PostgreSQL (production)

Keep the default backend and store the connection URI in an owner-only secret
file:

```sh
echo "postgresql://merovingian:secret@localhost/merovingian" \
  | sudo tee /etc/merovingian/db-uri
sudo chmod 600 /etc/merovingian/db-uri
sudo chown merovingian:merovingian /etc/merovingian/db-uri
```

```ini
database.backend=postgresql
database.uri_file=/etc/merovingian/db-uri
database.role=runtime
database.pool_size=16
```

Use `database.role=migration` only with the offline migration tool. The live
server requires `database.role=runtime`.

### Offline migration planning

`merovingian-db-migrate` plans schema migrations without starting the runtime:

```sh
merovingian-db-migrate --plan 1 2 --migrations migrations/
```

The live server applies pending migrations automatically on startup.

## Running the server

### Command-line interface

```text
merovingian-server [--dry-run]
merovingian-server [--dry-run] --config <path>
merovingian-server [--config <path>] --bootstrap-admin <localpart> \
  --bootstrap-admin-password-file <path>
merovingian-server --check-config <path>
merovingian-server --plan-config-reload <current> <next>
merovingian-server --help
merovingian-server --version
```

| Flag | Purpose |
|---|---|
| `--config <path>` | Path to `merovingian.conf`. |
| `--dry-run` | Validate config and print the startup summary without binding listeners. |
| `--check-config <path>` | Validate the config file and exit. |
| `--bootstrap-admin <localpart>` | Create an admin account and exit. Requires `--bootstrap-admin-password-file`. |
| `--bootstrap-admin-password-file <path>` | File containing the bootstrap admin password. |
| `--plan-config-reload <current> <next>` | Compare two configs and report reloadability. |
| `--debug` | Enable debug-level console diagnostics. |
| `--log-file <path>` | Write trace/debug diagnostics to a file. |

### Start the server

```sh
merovingian-server --config /etc/merovingian/merovingian.conf
```

The process binds the configured listeners, launches the federation worker
(when enabled), runs a hardening self-check, and logs `Listeners active;
awaiting traffic. Send SIGINT or SIGTERM to stop.`

### systemd

Distro packages install `packaging/systemd/merovingian.service`. Enable and start
it:

```sh
systemctl enable --now merovingian.service
```

The unit runs as the `merovingian` user, restricts filesystem access to
`/var/lib/merovingian` and `/var/log/merovingian`, and applies
`NoNewPrivileges`, `PrivateTmp`, `ProtectSystem=strict`, and other hardening.

### Smoke test

After starting:

```sh
curl -s http://127.0.0.1:8008/_matrix/client/v3/version
```

Expect a JSON response listing supported Matrix client-server versions.

## Reverse proxy

Merovingian is designed to sit behind a reverse proxy. The proxy should:

- Own public TLS.
- Forward `Origin` and `Authorization` headers unmodified.
- **Not** add `Access-Control-Allow-*` headers for `/_matrix/` routes.
- Route `/_matrix/client/` and `/_matrix/media/` to `127.0.0.1:8008`.
- Route `/_matrix/federation/` and `/_matrix/key/` to `127.0.0.1:8009`.
- Serve `/.well-known/matrix/client` and `/.well-known/matrix/server` directly
  (or forward them, but keep their own CORS headers).

Complete copy-paste configs for nginx, Apache httpd, Caddy, Traefik, HAProxy,
and Cloudflare are in
[`docs/configuration.md#reverse-proxy-examples`](configuration.md#reverse-proxy-examples).

## User management

### Create the first admin

Use `--bootstrap-admin` before opening public registration:

```sh
merovingian-server --config /etc/merovingian/merovingian.conf \
  --bootstrap-admin alice \
  --bootstrap-admin-password-file /run/merovingian/admin-pw
```

### Enable public registration

```ini
security.registration.enabled=true
security.registration.require_token=true
security.registration.token_file=/etc/merovingian/registration-token
```

Generate the token:

```sh
openssl rand -base64 48 | sudo tee /etc/merovingian/registration-token
sudo chmod 600 /etc/merovingian/registration-token
```

### Register a user

```sh
TOKEN=$(sudo cat /etc/merovingian/registration-token)
curl -s -X POST http://127.0.0.1:8008/_matrix/client/v3/register \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"alice\",\"password\":\"CorrectHorse7!\", \
       \"auth\":{\"type\":\"m.login.registration_token\",\"token\":\"$TOKEN\"}}"
```

### Log in and get an access token

```sh
curl -s -X POST http://127.0.0.1:8008/_matrix/client/v3/login \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "m.login.password",
    "identifier": {"type": "m.id.user", "user": "@alice:example.org"},
    "password": "CorrectHorse7!",
    "device_id": "MY_DEVICE"
  }'
```

## Federation

### Enable or disable federation

Federation is enabled by default:

```ini
security.federation.enabled=true
```

Set it to `false` to run a non-federating server.

### Allow-list federation

```ini
security.federation.default_policy=deny
security.federation.allowed_servers=matrix.org,example.net
security.federation.denied_servers=bad.example
```

Deny-by-default federation requires a non-empty `allowed_servers` list.

### Federation worker

When federation is enabled, the worker is mandatory. Startup fails if the worker
cannot be launched. Tune `federation.worker.shards` to distribute CPU across
multiple worker processes for busy servers.

### Federation join diagnostics

Large remote room joins are the most resource-intensive federation operation.
If joins to big rooms time out or return `502`:

- Increase `security.federation.join_timeout`.
- Increase `security.federation.join_response_max_size` (requires restart).
- Tune `federation.worker.relay_threads` for more concurrent join traffic.
- Check that `security.federation.join_race_deadline` fits within your reverse
  proxy's own request timeout.

## Media repository

### Local uploads

- `security.media.max_upload_size` bounds local uploads. Match this value in
  your reverse proxy (e.g. `client_max_body_size` in nginx).
- Unknown MIME types are quarantined by default.
- Encrypted-room attachments are uploaded as `application/octet-stream`; keep
  that type in the allow-list.

### Remote media fetching

Remote fetching is opt-in:

```ini
security.media.remote_fetch_enabled=true
```

Fetched bytes default to `quarantine` because federated origins are unaccountable
and no AV engine is integrated today.

### Sandbox

`security.media.decode_in_sandbox=true` runs the thumbnail/decoder worker as a
separate process with resource limits and (on Linux) a seccomp-bpf filter. Keep
it enabled.

## Logging and diagnostics

### Console and file logging

```sh
merovingian-server --debug --log-file /var/log/merovingian/debug.log \
  --config /etc/merovingian/merovingian.conf
```

`--debug` lowers the default log level to `debug`. `--log-file` writes
trace/debug diagnostics to the selected file.

### Per-module log levels

```ini
log_modules.http_server=info
log_modules.client_server=debug
log_modules.rate_limit=debug
log_modules.*=debug
```

Restart the server for log-module changes to take effect. See
[`docs/log-filtering.md`](log-filtering.md) for the module list.

### Audit log

High-signal events (rate-limit hits, login rejections, access-token rejections,
request rejections, registration policy denials) are written to the structured
audit log. Query it through the admin endpoint:

```sh
curl 'http://127.0.0.1:8008/_merovingian/admin/audit?category=policy'
```

## Maintenance

### Backups

Back up at least:

- The database (PostgreSQL dump or SQLite file).
- `/etc/merovingian/master-key` (required to decrypt the signing secret stored
  in the database).
- `/etc/merovingian/merovingian.conf`.

Without the master key, the signing secret cannot be recovered from the
database.

### Upgrades

1. Review the [`CHANGELOG.md`](../CHANGELOG.md) for the target version.
2. Stop the server.
3. Back up the database and master key.
4. Install the new package or tarball.
5. Validate the config with `--check-config`.
6. Start the server.

Schema migrations are applied automatically on startup.

### Version and release metadata

The canonical version is `meson.build`. When the version changes, every file
listed in [`docs/versioning.md`](versioning.md) must be updated in the same
commit.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `duplicate configuration key` at startup | Two active `database.backend` lines or any other duplicate key. | Remove the duplicate. |
| `Config validation failure` (exit 79) | Unsafe listener bind, missing secret file, open registration without token, etc. | Read the specific message and adjust `merovingian.conf`. |
| Client shows "Failed to connect" | Proxy emits duplicate `Access-Control-Allow-Origin` headers, or `/.well-known/matrix/client` is missing/404. | Remove proxy CORS headers; serve the well-known discovery file. |
| `429 Too Many Requests` for all clients | `server.trusted_proxies` is unset behind a reverse proxy. | Set `server.trusted_proxies` and ensure the proxy overwrites `X-Forwarded-For` with the direct peer IP. |
| `502 send_join failed: timeout` | Large room join exceeds `security.federation.join_timeout` or the proxy's request timeout. | Raise `join_timeout` and `join_race_deadline`; ensure they fit inside the proxy timeout. |
| `502 send_join failed: response_too_large` | `send_join` response exceeds `security.federation.join_response_max_size`. | Raise the value and restart both main and worker processes. |
| Federation worker does not start | `merovingian-fed-worker` binary is missing or `federation.worker.binary` points to the wrong path. | Check binary location and permissions. |
| Encrypted media downloads fail | `application/octet-stream` was removed from `security.media.allowed_mime_types`. | Restore it. |

## Security checklist

Before opening a server to real users:

- [ ] `server.name` and `server.public_baseurl` match the public DNS/TLS setup.
- [ ] A 32-byte master key is generated and stored with owner-only permissions.
- [ ] PostgreSQL is used for production; SQLite is only for evaluation.
- [ ] Database URI, registration token, and TLS private keys are owner-only and
      outside web roots.
- [ ] A reverse proxy terminates public TLS; Merovingian binds to loopback only.
- [ ] `server.trusted_proxies` is set so per-IP rate limits work correctly.
- [ ] The proxy overwrites `X-Forwarded-For` with the direct peer IP.
- [ ] The proxy does **not** emit `Access-Control-Allow-*` headers for
      `/_matrix/` traffic.
- [ ] Public registration is token-protected (or disabled).
- [ ] Federation deny/allow lists match your trust model.
- [ ] `security.federation.require_valid_tls` and
      `security.federation.verify_json_signatures` are `true`.
- [ ] `security.media.decode_in_sandbox` is `true`.
- [ ] `security.logging.redact_tokens` and
      `security.logging.redact_event_content` are `true`.
- [ ] Log file permissions are restricted.
- [ ] Regular database and master-key backups are configured.

For the complete security architecture and threat model, see
[`docs/threat-model.md`](threat-model.md) and
[`docs/hardening.md`](hardening.md).
