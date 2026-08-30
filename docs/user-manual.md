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
- [Verifying release artifacts](#verifying-release-artifacts)
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
  loopback (`127.0.0.1:8008` and `127.0.0.1:8009`) with TLS disabled and
  `reverse_proxy=true`. A reverse proxy owns public TLS and routes traffic to
  the loopback listeners. Public listeners must use TLS and set
  `reverse_proxy=false`; loopback cleartext without an explicit reverse-proxy
  declaration is rejected at startup.
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
dpkg -i merovingian_0.10.38_amd64.deb

# Fedora/RHEL example
dnf install merovingian-0.10.38-1.fc40.x86_64.rpm
```

Packages create the `merovingian` system user and group, install the systemd
unit, and stage the example configuration at `/etc/merovingian/
merovingian.conf.example`.

### Install the portable static Linux tarball

For older Linux distributions, use the musl-linked tarball. It has no glibc or
runtime package dependencies.

```sh
tar xzf merovingian-0.10.38-linux-static-x86_64.tar.gz
cp merovingian-0.10.38-linux-static-x86_64/bin/merovingian-server /usr/local/bin/
cp merovingian-0.10.38-linux-static-x86_64/bin/merovingian-db-migrate /usr/local/bin/
cp merovingian-0.10.38-linux-static-x86_64/libexec/merovingian/merovingian-fed-worker \
   /usr/local/libexec/merovingian/
```

The static tarball does **not** receive automatic dependency security updates;
redeploy a new tarball to pick up OpenSSL/LibSodium/libcurl fixes.

#### Verifying release artifacts

Every release artifact is accompanied by a detached GPG signature (`.asc`) and a
SHA-256 checksum. Verification uses the maintainer signing key fingerprint
published in [`docs/release-process.md`](release-process.md):

```sh
# Import the release signing key.
gpg --keyserver keys.openpgp.org --recv-keys 66DFCC50187C8E46B5ED85FD92A3A264F0A7BE20

# Download the tarball, signature, and checksum for your platform, then verify
the signature.
gpg --verify merovingian-0.10.38-linux-static-x86_64.tar.gz.asc \
             merovingian-0.10.38-linux-static-x86_64.tar.gz

# Verify the checksum.
sha256sum -c merovingian-0.10.38-linux-static-x86_64.tar.gz.sha256
```

A valid signature reports a "Good signature" from `The Merovingian Release
Signing Key`. An invalid or missing signature, or a mismatched checksum, is a
distribution failure: do not install the artifact.

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

### Fail-closed startup

Startup rejects configuration before doing any runtime work — binding
listeners, scaffolding the database, or launching federation workers — when
parser or validation findings are present. `--check-config <path>` runs the
same file metadata, parser, validation, and secret-file permission checks,
but exits before the startup runtime summary.

Rejected cases include:

- unreadable or missing config path
- unsafe config file permissions, or unsafe existing secret file permissions
- oversized config file or config line
- duplicate, unknown, or malformed config keys
- invalid boolean or unsigned-integer values
- empty required server/listener/database values
- non-HTTPS public base URL
- malformed listener bind address
- a cleartext listener on a non-loopback interface
- a TLS listener without certificate/private-key paths, or a missing/unsafe
  configured certificate or private-key file
- open registration without a token requirement, or token-protected
  registration without a registration token file
- disabled default encryption for new rooms, or disabled direct-message
  encryption requirement
- invalid federation default policy, or deny-by-default federation without
  allowed servers
- malformed federation allowed/denied server entries
- disabled federation TLS validation or JSON signature verification
- missing private/loopback federation deny ranges
- invalid federation transaction size or remote timeout
- invalid media upload size
- disabled private-IP blocking for remote media fetches, or invalid media
  remote-fetch timeout
- trust-safety transport enabled without a policy server URL, a non-HTTPS
  policy server URL, or an invalid policy server timeout
- disabled sandboxed media decoding
- disabled token or event-content log redaction

### Size and duration value formats

Byte-size values accept a positive bounded size with one of these suffixes:
`B`, `KiB`, `MiB`, `GiB` (e.g. `security.media.max_upload_size=50MiB`).
Values such as `0MiB`, `50MB`, `-1MiB`, `50 MiB`, and `unbounded` are rejected.

Duration values accept a positive bounded duration with one of these
suffixes: `s`, `m` (e.g. `security.federation.remote_timeout=60s`). Values
such as `0s`, `30`, `30ms`, and `forever` are rejected.

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

Wildcard `*` is the safe default for Matrix because clients authenticate with
`Authorization: Bearer` tokens, not browser cookies. The parser rejects
`allow_credentials=true` combined with a wildcard origin, since the CORS spec
forbids that combination. CORS is **not** hot-reloadable — a change to any
`server.cors.*` key requires a restart.

#### HTTP transport — `server.http.*`

Controls HTTP/1.1 persistent connections (keep-alive). Connections are served
as sequential request rounds; each kept-alive connection is parked for at most
`keep_alive_idle_seconds` while waiting for the client's next request, and
each parked connection holds one request-pool worker thread, so
`keep_alive_max_connections` caps the process-wide total.

| Key | Default | When to change |
|---|---|---|
| `server.http.keep_alive` | `true` | Set `false` to restore strict one-request-per-connection behaviour (e.g. in front of a proxy that pools upstream connections itself). |
| `server.http.keep_alive_idle_seconds` | `15` | Idle window per kept-alive connection, seconds, 1..300. Raise for chatty API clients that re-use connections; lower to free worker threads sooner. |
| `server.http.keep_alive_max_connections` | `8` | Process-wide cap on connections parked awaiting a next request, 1..4096. Beyond the cap the server answers `Connection: close`. Raise only alongside a larger request pool. |

The parser rejects idle windows outside 1..300 seconds and caps outside
1..4096. These keys are read when the listeners start and are **not**
hot-reloadable — a change to any `server.http.*` key requires a restart.

#### TURN server — `server.turn.*`

VoIP clients request TURN relay credentials through
`GET /_matrix/client/v3/voip/turnServer`. When no TURN server is configured the
endpoint returns an empty JSON object so clients gracefully disable relay
support.

| Key | Default | When to change |
|---|---|---|
| `server.turn.server` | (empty) | TURN server URI advertised to clients, e.g. `turn:turn.example.org:3478?transport=udp`. Leave empty to keep the endpoint returning `{}`. |
| `server.turn.username` | (empty) | Static username issued to authenticated clients. Required when `server.turn.server` is set. |
| `server.turn.password` | (empty) | Static password issued alongside the username. Required when `server.turn.server` is set. |
| `server.turn.ttl_seconds` | `86400` | Credential lifetime advertised in the response. |

> **Security note.** Shared-secret, time-limited TURN usernames are not yet
> implemented; the current implementation issues the configured static
> credentials to every authenticated client. Only supply credentials that are
> acceptable for all users of this homeserver, or run a TURN server that does not
> require authentication.

#### OIDC discovery — `server.oidc.*`

`GET /_matrix/client/v1/auth_metadata` (MSC2965) returns 404 `M_UNRECOGNIZED`
until `server.oidc.enabled=true`. Merovingian does not implement an OAuth 2.0
authorization server itself — these keys only describe an external one for
clients to discover.

| Key | Default | When to change |
|---|---|---|
| `server.oidc.enabled` | `false` | Set `true` once the endpoints below point at a real OIDC provider. |
| `server.oidc.issuer` | (empty) | **Required when enabled.** Must be a valid HTTPS URL with no query or fragment. |
| `server.oidc.authorization_endpoint` | (empty) | The provider's authorization endpoint. |
| `server.oidc.token_endpoint` | (empty) | The provider's token endpoint. |
| `server.oidc.registration_endpoint` | (empty) | The provider's dynamic client registration endpoint, if supported. |
| `server.oidc.revocation_endpoint` | (empty) | The provider's token revocation endpoint, if supported. |
| `server.oidc.device_authorization_endpoint` | (empty) | The provider's device authorization endpoint, if supported. |
| `server.oidc.account_management_uri` | (empty) | A user-facing account management page, if the provider offers one. |
| `server.oidc.account_management_actions_supported` | (empty) | Comma-separated list of account-management actions the URI above supports. |

#### Identity Service API — `server.identity_server.*`

Used for 3PID (email/phone) invites, binds, unbinds, and `requestToken`
flows. With `trusted_servers` empty (the default) every operation that needs
an identity server fails closed rather than silently minting tokens locally.

| Key | Default | When to change |
|---|---|---|
| `server.identity_server.trusted_servers` | (empty) | Comma-separated allow-list of identity server base URLs (must be HTTPS). A 3PID operation naming an `id_server` outside this list is refused. |
| `server.identity_server.default_server` | (empty) | Identity server used when a client omits `id_server`. Must be HTTPS and must also appear in `trusted_servers`. |
| `server.identity_server.allowed_bind_domains` | (empty) | Restricts which email/phone domains a user may bind a 3PID for. Empty allows any domain. |
| `server.identity_server.connect_timeout_seconds` | `10` | Outbound connect timeout for identity server HTTP calls. |
| `server.identity_server.total_timeout_seconds` | `30` | Outbound total timeout for identity server HTTP calls. Must be `>=` `connect_timeout_seconds`. |

#### Push notifications — `server.push.*`

Push Gateway API delivery (Matrix v1.19 push-gateway-api / CS API
push-notifications module) is **disabled by default** — pushers can still be
registered via `POST /pushers/set`, but no notification is ever sent to a
gateway until `server.push.enabled=true`. This mirrors `server.oidc.enabled`'s
pattern so merging this capability cannot start sending traffic to
client-supplied gateway URLs on upgrade.

| Key | Default | When to change |
|---|---|---|
| `server.push.enabled` | `false` | Set `true` to actually deliver notifications to registered pushers' gateways. |
| `server.push.connect_timeout_seconds` | `10` | Outbound connect timeout when contacting a pusher's gateway URL (client-supplied, untrusted). |
| `server.push.total_timeout_seconds` | `30` | Outbound total timeout for a gateway push request. Must be `>=` `connect_timeout_seconds`. |

#### Listeners — `listeners.client.*` and `listeners.federation.*`

| Key | Default | When to change |
|---|---|---|
| `listeners.client.bind` | `127.0.0.1:8008` | Client-server API and media. |
| `listeners.client.tls` | `false` | Set `true` only if binding to a public interface without a reverse proxy. |
| `listeners.client.reverse_proxy` | `true` | Set `false` for a direct public TLS listener; must be `true` for loopback cleartext. |
| `listeners.client.tls_certificate_file` | (empty) | Required when `tls=true`. |
| `listeners.client.tls_private_key_file` | (empty) | Required when `tls=true`. |
| `listeners.federation.bind` | `127.0.0.1:8009` | Federation and key API. Must be separate from the client listener. |
| `listeners.federation.tls` | `false` | Set `true` only for direct public federation without a proxy. |
| `listeners.federation.reverse_proxy` | `true` | Set `false` for a direct public TLS listener; must be `true` for loopback cleartext. |
| `listeners.federation.tls_certificate_file` | (empty) | Required when federation TLS is enabled. |
| `listeners.federation.tls_private_key_file` | (empty) | Required when federation TLS is enabled. |

A listener with `tls=false` must bind to a loopback address (`127.0.0.1`,
`localhost`, `::1`, or `[::1]`) **and** declare `reverse_proxy=true`, which is
Merovingian's default and matches a reverse-proxy deployment. A non-loopback
(public) listener must use TLS with `reverse_proxy=false`. When `tls=true`
both `tls_certificate_file` and `tls_private_key_file` must be set:

```ini
# Direct public client listener (no reverse proxy)
listeners.client.bind=0.0.0.0:8443
listeners.client.tls=true
listeners.client.reverse_proxy=false
listeners.client.tls_certificate_file=/etc/merovingian/client.pem
listeners.client.tls_private_key_file=/etc/merovingian/client.key

# Direct public federation listener (no reverse proxy)
listeners.federation.bind=0.0.0.0:8448
listeners.federation.tls=true
listeners.federation.reverse_proxy=false
listeners.federation.tls_certificate_file=/etc/merovingian/federation.pem
listeners.federation.tls_private_key_file=/etc/merovingian/federation.key
```

Configured certificate files must be regular, non-executable, and not
group/other-writable. Configured private-key files must additionally be
owner-only. Startup loads the certificate chain and private key, verifies
the key matches the certificate, and fails closed if OpenSSL rejects either
file. The client listener defaults to `127.0.0.1:8008`; the federation
listener defaults to `127.0.0.1:8009` so a reverse proxy can own the public
federation port `8448`.

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

The token file is read on startup and should contain the registration token
on its first line. Treat it as a secret — owner-only, non-executable, outside
web roots, and rotated whenever it may have been shared too broadly. The
token is hashed with Argon2id at load time; only the hash is retained in
process memory and the plaintext is zeroised after hashing. Changing the
token-file path requires a restart. Successful public registration always
creates a normal user; admin accounts can only be created through
`--bootstrap-admin`.

#### At-rest secret protection — `security.secrets.*`

| Key | Default | When to change |
|---|---|---|
| `security.secrets.master_key_file` | `/etc/merovingian/master-key` | Path to the 32-byte master key file. |

When a master key is configured, the Ed25519 server signing secret is
encrypted at rest with `secret_box` (`secretbox:v1:...`) before being stored
in the database. If no master key is configured, the secret is stored as a
legacy plaintext base64 value for backward compatibility and a one-time
diagnostic warns the operator. Rotating the signing key after enabling the
master key re-encrypts the active secret under the new at-rest format.

#### Token lifetimes — `security.*_token_lifetime_ms`

| Key | Default | When to change |
|---|---|---|
| `security.access_token_lifetime_ms` | `3600000` (1 hour) | Milliseconds; `0` disables expiry. |
| `security.refresh_token_lifetime_ms` | `2592000000` (30 days) | Milliseconds; `0` disables expiry. |

`/login` and `/refresh` advertise `expires_in_ms` from
`security.access_token_lifetime_ms`, so the advertised TTL always matches the
enforced one. A token past its TTL is rejected even when its session is not
revoked — the request returns `401 M_UNKNOWN_TOKEN` and the audit log records
`access_token.rejected` with reason `token expired`. Existing rows written
without an expiry remain valid, so upgrading does not invalidate legacy
sessions.

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

`join_parallelism` bounds *concurrency*, not *total elapsed time*. A room
with a large `via` candidate list races in batches of `join_parallelism`,
and with no overall bound the whole race could take
`ceil(candidate_count / join_parallelism) * join_timeout` — many minutes for
a large `via` list. `join_race_deadline` closes that gap: it is the overall
wall-clock budget for the *entire* race, independent of the per-candidate
`join_timeout`. When it elapses without a winner, `join_room` returns `502`
immediately; candidates still in flight are parked in a background queue and
drained on shutdown. It cannot be disabled via config, only extended.
`join_max_candidates` caps how many `via`-derived candidates are actually
raced — every candidate is spawned as an OS thread immediately, throttled to
*run* by `join_parallelism` but not to *spawn*, so an unbounded `via` list
otherwise means unbounded upfront thread creation.

A `send_join` response's `state` array carries one `m.room.member` event per
room member, each signed by that member's home server; `join_room` verifies
every signature before the event enters the graph rather than trusting the
resident server's response wholesale. `join_state_key_parallelism` caps
concurrent remote signing-key resolutions for that verification pass —
distinct `(sender_domain, key_id)` pairs are deduplicated first, so it bounds
concurrent *distinct home servers* contacted, not concurrent events. Fast
join persists the room's own critical state (create, power levels, join
rules, history visibility, our own membership) and the auth chain
synchronously before `join_room` returns; the bulk of `state` — every other
member's `m.room.member` event — is verified and persisted by a background
task afterward, governed by the same parallelism cap. See
[`docs/threat-model.md`](threat-model.md) for the partial-state trade-off
this implies.

`join_response_max_size` exists because a `send_join` response embeds the
room's full current state as a single HTTP response body, which for a large
room routinely exceeds the general 16 MiB response cap every other
federation call uses. It also sizes the federation-worker IPC channel's
frame budget, which is fixed for the worker process's lifetime — raising
this value takes effect only after both the main process and the worker
restart.

#### Federation inbound abuse controls — `security.federation.*`

Inbound `/send/{txnId}` transactions are authenticated by `X-Matrix` request
signatures before buckets are charged. Buckets are keyed by the verified
remote origin, not the event sender ID, because a remote server can relay
events for many users and an abusive remote can rotate sender IDs.

| Key | Default | When to change |
|---|---|---|
| `security.federation.max_transaction_pdus` | `50` | Hard cap on PDUs per inbound `/send` transaction. Matrix v1.19 caps this at `50`; higher values are rejected. |
| `security.federation.max_transaction_edus` | `100` | Hard cap on EDUs per inbound `/send` transaction. Matrix v1.19 caps this at `100`; higher values are rejected. |
| `security.federation.per_origin_transaction_rate` | `120/60s` | Maximum accepted `/send` transactions per verified remote origin per window. |
| `security.federation.per_origin_pdu_rate` | `600/60s` | Weighted PDU budget per verified remote origin per window — a transaction with 40 PDUs consumes 40 units. |
| `security.federation.per_origin_edu_rate` | `1200/60s` | Weighted EDU budget per verified remote origin per window. |

Rate values use `N/Ws` or `N/Wm` syntax (e.g. `300/60s`). All five keys are
reloadable. An origin that exceeds a bucket gets `429 M_LIMIT_EXCEEDED` for
the transaction and a `federation.rate_limited` audit event; invalid
individual PDUs inside an otherwise-valid transaction still report per-PDU
errors in the `200` transaction response, matching Matrix retry semantics
and avoiding destination-wide backoff for one bad event.

#### Federation outbound delivery controls

The `per_origin_*` keys above apply only to inbound `/send` traffic; they do
not throttle Merovingian's own delivery to other homeservers. Outbound
federation queues an `OutboundTransaction` record per destination, and a
dispatch worker drains that queue with destination retry state, a circuit
breaker, and exponential backoff — a failing or slow destination is delayed
before the next attempt so it does not spin the sender or block unrelated
destinations. Outbound HTTP also applies the same private/loopback address
rejection and pinned resolved addresses used during federation discovery.

| Key | Default | Reload | Notes |
|---|---|---|---|
| `security.federation.remote_timeout` | `60s` | reloadable | General outbound federation HTTP timeout for calls other than the join/leave dance. |
| `security.federation.deny_ip_ranges` | private/loopback ranges | reloadable | Blocks discovered outbound federation targets in private/loopback address space. |
| `federation.worker.relay_threads` | `32` | requires restart | Thread pool for worker paths that can block on outbound HTTP or synchronous main-process relays. |

#### Federation worker — `federation.worker.*`

When a user joins a large federated room, inbound PDU verification, state
resolution, and the membership state machine can saturate the main thread
pool and make all connected clients unresponsive. The federation worker
moves that work into one or more dedicated child processes, each with its
own thread pool. It is **mandatory** when federation is enabled; startup
fails fatally if the worker binary cannot be launched, and there is no
in-process fallback — requests return `503` while a crashed worker restarts.

| Key | Default | When to change |
|---|---|---|
| `federation.worker.threads` | `4` | Thread pool for endpoints answered entirely from the worker's own local snapshot (`make_join`/`make_leave`/`make_knock`, `backfill`, directory/state queries, `get_missing_events`, `hierarchy`) — these never block on main, so this can stay small. |
| `federation.worker.relay_threads` | `32` | Thread pool for endpoints that can block on a synchronous IPC round-trip to main (PDU-bearing `send`, `send_join`/`send_leave`/`send_knock`, `invite`, profile/key queries, `event/{eventId}`) or on outbound HTTP. Deliberately separate and generously sized from `threads`, since sharing one pool would let a burst of slow relay calls starve the fast local endpoints — see [`docs/architecture.md`](architecture.md), "Federation worker relay pool separation". |
| `federation.worker.shards` | `2` | Number of independent worker processes. Requests are routed by `fnv1a_32(room_id) % shards`; non-room endpoints go to shard 0. Must be `>= 1`. |
| `federation.worker.request_timeout_seconds` | `30` | Base per-request IPC timeout in seconds. The actual IPC timeout for inbound federation requests is `max(request_timeout_seconds, security.federation.remote_timeout) + 10 s`, so a worker-side outbound HTTP call can complete before main gives up. A request slower than the effective timeout returns `504` to the remote server. |
| `federation.worker.apply_hardening` | `true` | Apply seccomp/capability sandboxing to workers. Keep `true` in production. |
| `federation.worker.binary` | (empty) | Absolute path to `merovingian-fed-worker`; empty uses the compile-time libexec path (`$libexecdir/merovingian/merovingian-fed-worker`). |

The worker communicates with the main process over an `AF_UNIX SOCK_STREAM`
socket pair inherited at spawn. Every frame is encrypted with an ephemeral
`crypto_kx` key exchange and `crypto_secretstream_xchacha20poly1305` AEAD —
no sensitive material crosses the channel in plaintext. The server signing
key is never forwarded; the worker reads it from the same database, and
client access tokens are stripped from every request before forwarding. If
the worker crashes, the supervisor restarts it with exponential back-off
(1s, 2s, 4s, 8s, capped at 30s).

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

> **Encrypted-room media can never be scanned, under any configuration, by
> design.** Matrix E2EE attachments are encrypted client-side before upload;
> the homeserver only ever receives and stores an opaque
> `application/octet-stream` ciphertext blob and never holds the decryption
> key — that key travels only inside the (also encrypted) room event, which
> the server cannot read either. No setting below, no proxy placement, and no
> future scanner integration changes this without breaking E2EE's
> confidentiality guarantee. Anything below that mentions a "scanner
> verdict" applies only to plaintext media in unencrypted rooms.

Two `security.media.*` keys are not fully wired end to end yet:
`security.media.enable_av_scanner` is parsed, but does not configure or
launch an antivirus engine — it only changes how the media policy treats a
scanner verdict supplied by an upstream caller. `security.media.remote_fetch_timeout`
is parsed and validated, but the live remote-fetch path still uses
hard-coded discovery and outbound HTTP timeouts.

`local_upload_policy` and `remote_fetch_media_policy` select the acceptance
disposition for authenticated local uploads and for bytes fetched from a
federated origin, independently. Each accepts:

- `allow` — accept unconditionally; the scanner verdict is ignored.
- `allow-after-scan` — accept only when the scanner verdict is clean;
  quarantine or reject otherwise. This is the only behaviour that existed
  before these keys were introduced.
- `quarantine` — always hold for manual admin review via the
  `/_merovingian/admin/media/{quarantine,release,remove}` routes.
- `deny` — reject unconditionally.

`remote_fetch_media_policy` defaults to `quarantine` rather than mirroring
`local_upload_policy`'s `allow-after-scan` default: unlike a local upload, a
federated origin has no accountable local identity behind it, and Merovingian
does not run a real AV scanner for *any* media source today, so there is
never a genuine "clean" verdict to trust for remote-fetched bytes. Operators
who accept that risk, or who front the server with a real scanning proxy
that populates the scanner verdict, can set this to `allow-after-scan` or
`allow` explicitly.

#### Trust and safety — `security.trust_safety.*`

The trust-safety transport is opt-in and fail-closed by default.

| Key | Default | When to change |
|---|---|---|
| `security.trust_safety.enabled` | `false` | Set `true` to consult a remote policy service for registration, room creation, inbound federation, and media downloads. |
| `security.trust_safety.policy_server_url` | (empty) | HTTPS URL of the policy service. Required when enabled. |
| `security.trust_safety.policy_server_timeout` | `5s` | Policy request timeout. |
| `security.trust_safety.policy_server_allow_without_result` | `false` | Set `true` to allow the guarded workflow when the policy service is unreachable. Defaults fail-closed. |

When enabled, Merovingian POSTs a small JSON decision request — `surface`,
`entity`, `server_name` — to the configured HTTPS endpoint. The response
body is expected to be JSON with at least:

- `action` — one of `allow`, `deny`, `quarantine`, `lock_account`,
  `suspend_account`.
- `rule_id` — optional, recommended for audit correlation.
- `summary` / `reason` — optional operator-facing text.

If the policy server is unreachable, returns a non-2xx status, omits a
usable decision, or sends malformed JSON, the guarded workflow is rejected
unless `security.trust_safety.policy_server_allow_without_result=true`.

#### Logging redaction — `security.logging.*`

| Key | Default | When to change |
|---|---|---|
| `security.logging.redact_tokens` | `true` | Keep `true` so tokens do not leak into logs. |
| `security.logging.redact_event_content` | `true` | Keep `true` so message content does not leak into logs. |
| `security.logging.structured` | `true` | Structured log format. |

#### Client rate limits — `client_rate_limits.*`

Two independent wall-clock token-bucket tiers are enforced on every
client-server request:

- **Per-IP**, keyed by `(effective_client_ip, normalized_route)`.
- **Per-user**, keyed by the authenticated `user_id` plus the normalized
  route for requests that present a valid access token.

The longest matching `<target>` prefix wins; path parameters such as
`roomId`, `deviceId`, and `mediaId` are coalesced into placeholders so a
single cap covers all rooms/devices/media. Every entry rejects a zero-window
or zero-cap policy at startup. Changes require a server restart.

| Key | Default | When to change |
|---|---|---|
| `client_rate_limits.per_ip.<target>` | see defaults below | Per-IP cap for requests matching `<target>` prefix. |
| `client_rate_limits.per_user.<target>` | see defaults below | Per-user cap keyed by authenticated `user_id`. |
| `client_rate_limits.default_per_ip` | `90/60s` | Fallback cap for unmatched targets. |

Default route-aware policies applied when no override is configured:

| Endpoint class | Default policy |
|---|---|
| Login / registration | 20/60s per IP; 5/60s per user on `/login` |
| Device and key APIs | 30/60s per IP |
| Media APIs | 20/60s per IP |
| Generic client APIs | 90/60s per IP fallback |

Example overrides:

```ini
client_rate_limits.per_ip./_matrix/client/v3/login=20/60s
client_rate_limits.per_user./_matrix/client/v3/login=5/60s
client_rate_limits.default_per_ip=90/60s
```

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
Restart-required keys affect stable process identity or secret-source
selection; reloadable keys are runtime policy or limit values intended to be
applied through a future reload path without a full homeserver restart.
Configuration parsing and validation are restart-safe today, but the live
reload control path (SIGHUP/admin socket) is not yet wired — `--plan-config-reload`
only reports what *would* happen.

| Key or key group | Policy |
|---|---|
| `server.name` | Restart required |
| `database.uri_file` | Restart required |
| `database.role` | Restart required |
| `listeners.*.tls_certificate_file` | Restart required |
| `listeners.*.tls_private_key_file` | Restart required |
| `security.federation.join_response_max_size` | Restart required |
| `federation.worker.*` | Restart required |
| `server.cors.*` | Restart required |
| `server.http.*` | Restart required |
| `security.secrets.master_key_file` | Restart required |
| `client_rate_limits.*` | Restart required |
| `log_modules.*` | Restart required |
| `server.identity_server.*` | Restart required |
| `server.push.*` | Restart required |
| `database.pool_size` | Reloadable |
| `server.turn.*` | Reloadable |
| `security.trust_safety.*` | Reloadable |
| `security.access_token_lifetime_ms` / `security.refresh_token_lifetime_ms` | Reloadable |
| Other `listeners.*` keys | Reloadable |
| `security.registration.*` | Reloadable |
| `security.encryption.*` | Reloadable |
| `security.federation.*` (except `join_response_max_size`) | Reloadable |
| `security.media.*` | Reloadable |
| `security.logging.*` | Reloadable |
| `server.oidc.*` | Reloadable |

`--plan-config-reload <current> <next>` compares two validated configs and
reports the reload action:

```text
Reload plan: changes=1 reloadable=1 restart_required=0
Reload action: reloadable
security.federation.remote_timeout=reloadable
```

```text
Reload plan: changes=1 reloadable=0 restart_required=1
Reload action: restart required
server.name=restart_required
```

```text
Reload plan: changes=0 reloadable=0 restart_required=0
Reload action: no changes
```

A successful plan always exits with status `0`, even when the action says a
restart is required, because the planning operation itself succeeded.

### Runtime config snapshot

The runtime config snapshot owns the currently validated in-memory config and
can apply a candidate config only when the reload plan has no
restart-required changes:

| Outcome | Meaning |
|---|---|
| `unchanged` | Candidate config matches the current runtime config. |
| `applied` | Candidate config changed only reloadable keys and replaced the in-memory snapshot. |
| `restart_required` | Candidate config changed at least one restart-required key and was not applied. |

The snapshot is an internal foundation for future live reload — it is not yet
connected to SIGHUP, an admin socket, or any external control API.

### Startup hardening self-check

Startup logs a fixed checklist of hardening signals and refuses to start
unless every check reports `enabled` (`src/main.cpp`). Most checks are real
compile-time macros or runtime probes (ELF inspection, `/proc/self/status`,
`pledge`/Capsicum queries, `getrlimit`/`prctl`); a check reports `unknown`
only when its probe cannot run on the current platform (e.g. the Linux-only
probes on non-Linux, non-BSD platforms), never as a placeholder.

| Check | Current signal source |
|---|---|
| `compiler hardening` | Compile-time stack-protector + FORTIFY_SOURCE + PIE macros |
| `linker hardening` | ELF probe (RELRO, bind-now, noexecstack); `unknown` for statically-linked binaries |
| `PIE` | ELF probe; `unknown` if the probe cannot run or the binary is static |
| `RELRO` | ELF probe |
| `stack protector` | Compile-time macro |
| `FORTIFY_SOURCE` | Compile-time macro |
| `seccomp` | Runtime probe via `/proc/self/status` (Linux); `unknown` if the filter isn't applied or the platform isn't Linux |
| `pledge/unveil` | Runtime probe on OpenBSD; reports `enabled` (not applicable) on other platforms |
| `capsicum` | Runtime probe on FreeBSD; reports `enabled` (not applicable) on other platforms |
| `privilege drop` | Runtime non-root check on Linux; `unknown` on platforms without a probe |
| `filesystem restrictions` | Runtime non-root check on Linux; `unknown` on platforms without a probe |
| `core dump policy` | `getrlimit(RLIMIT_CORE)` probe on Linux; `unknown` elsewhere |
| `no_new_privs` | `PR_SET_NO_NEW_PRIVS` probe on Linux; `unknown` elsewhere |
| `capability bounding` | Capability bounding-set drop probe on Linux; `unknown` elsewhere |
| `secret redaction policy` | Enabled by validated logging defaults |

### Production packaging

Production package assets are intentionally separated from the bootstrap
config: `packaging/systemd/merovingian.service`, `packaging/openrc/merovingian`,
`packaging/rc.d/merovingian`, and `Dockerfile`. These assets are deployment
scaffolds until the production gates in
[`docs/todos/production-milestone.md`](todos/production-milestone.md) pass —
do not publish them as a production release while runtime listeners, durable
storage, federation verification, or hardening checks remain incomplete.

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
- Overwrite `X-Forwarded-For` with the direct TCP peer IP (never append to a
  client-supplied value) so `server.trusted_proxies` can enforce per-client
  rate limits correctly.

Set Merovingian's listeners to loopback cleartext behind the proxy:

```ini
listeners.client.bind=127.0.0.1:8008
listeners.client.tls=false
listeners.federation.bind=127.0.0.1:8009
listeners.federation.tls=false
server.trusted_proxies=127.0.0.1
```

### nginx example

Terminates TLS in nginx, serves the `.well-known` discovery JSON inline, and
routes client/media traffic to `8008` and federation/key traffic to `8009` by
path. Replace `matrix.example.org` with your `server.public_baseurl` host.

```nginx
server {
    listen 80;
    server_name matrix.example.org;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name matrix.example.org;

    ssl_certificate     /etc/letsencrypt/live/matrix.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/matrix.example.org/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-Frame-Options "DENY" always;
    # Do NOT add Access-Control-Allow-* here — Merovingian emits CORS headers
    # on all /_matrix/ responses; duplicate values break browser clients.

    location = /.well-known/matrix/client {
        default_type application/json;
        add_header Access-Control-Allow-Origin "*" always;
        return 200 '{"m.homeserver":{"base_url":"https://matrix.example.org"}}';
    }

    location = /.well-known/matrix/server {
        default_type application/json;
        add_header Access-Control-Allow-Origin "*" always;
        return 200 '{"m.server":"matrix.example.org:443"}';
    }

    location /_matrix/federation/ {
        proxy_pass http://127.0.0.1:8009;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        # $remote_addr, not $proxy_add_x_forwarded_for — the latter lets a
        # client forge another user's rate-limit bucket.
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    location /_matrix/key/ {
        proxy_pass http://127.0.0.1:8009;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    location /_matrix/client/ {
        proxy_pass http://127.0.0.1:8008;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    # Media needs its own block: falling through to the catch-all below
    # breaks upload/download CORS preflight, and nginx's default
    # client_max_body_size (1 MiB) silently 413s uploads before Merovingian
    # ever sees them. Match security.media.max_upload_size (default 50 MiB).
    location /_matrix/media/ {
        proxy_pass http://127.0.0.1:8008;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        client_max_body_size 50m;
    }

    location / {
        return 403;
    }
}

# Native federation listener for servers that skip .well-known delegation.
# Optional if every remote server follows .well-known/matrix/server, but
# harmless to keep.
server {
    listen 8448 ssl http2;
    server_name matrix.example.org;

    ssl_certificate     /etc/letsencrypt/live/matrix.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/matrix.example.org/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    location /_matrix/federation/ {
        proxy_pass http://127.0.0.1:8009;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    location /_matrix/key/ {
        proxy_pass http://127.0.0.1:8009;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    location / {
        return 403;
    }
}
```

**Apache** serves the discovery files from static files — create them once
before reloading:

```sh
mkdir -p /var/www/merovingian/.well-known/matrix
printf '{"m.homeserver":{"base_url":"https://matrix.example.org"}}' \
    > /var/www/merovingian/.well-known/matrix/client
printf '{"m.server":"matrix.example.org:443"}' \
    > /var/www/merovingian/.well-known/matrix/server
```

### Apache httpd example

This example assumes `mod_ssl`, `mod_headers`, `mod_proxy`,
`mod_proxy_http`, and `mod_rewrite` are enabled. Apache owns public ports `443`
and `8448`; Merovingian listens only on loopback ports `8008` and `8009`. The
`443` vhost handles both client and delegated federation traffic by path.

```apache
# Port 8448 must be declared before the VirtualHost blocks that use it.
Listen 8448

# ── HTTP → HTTPS redirect ─────────────────────────────────────────────────────
# Redirect all plain-HTTP requests to HTTPS so no Matrix credentials or tokens
# are ever sent in the clear.
<VirtualHost *:80>
    ServerName matrix.example.org
    RewriteEngine On
    RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>

# ── Primary HTTPS block (client-server API + delegated federation) ────────────
# Handles: Matrix clients (/_matrix/client/), media (/_matrix/media/), and
# federation delegated from port 443 via /.well-known/matrix/server.
<VirtualHost *:443>
    ServerName matrix.example.org

    # ── TLS ───────────────────────────────────────────────────────────────────
    # Terminate TLS here; Merovingian binds to cleartext loopback only.
    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/matrix.example.org/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/matrix.example.org/privkey.pem
    # Disable TLS 1.0 and 1.1 — both have known practical attacks.
    # Matrix spec requires TLS; older versions are non-compliant.
    SSLProtocol           -all +TLSv1.2 +TLSv1.3

    # ── Security response headers ──────────────────────────────────────────────
    # HSTS: instructs browsers to enforce HTTPS for one year and opts the domain
    # into browser-bundled preload lists for first-visit protection.
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    # Prevent MIME-type sniffing that could cause a browser to execute an
    # uploaded file served with a safe content-type.
    Header always set X-Content-Type-Options "nosniff"
    # Block this domain from being embedded in a frame on another origin,
    # protecting the login page against clickjacking.
    Header always set X-Frame-Options "DENY"
    # Do NOT add Access-Control-Allow-* here — Merovingian emits CORS headers on
    # all /_matrix/ responses. Adding them at the proxy level creates duplicate
    # values (e.g. "*, *") that browsers reject; clients show "Failed to connect"
    # even though the server returns HTTP 200.

    # ── Forwarding headers ────────────────────────────────────────────────────
    # Pass the original Host: header to Merovingian so it knows the server name
    # when constructing federation responses and verifying X-Matrix signatures.
    ProxyPreserveHost On
    # Tell Merovingian the downstream connection arrived over HTTPS.  Without
    # this, code that inspects the forwarded protocol sees cleartext.
    RequestHeader set X-Forwarded-Proto "https"
    # Overwrite X-Forwarded-For with the IP Apache received the TCP connection
    # from.  The unset+set pair prevents a client from injecting a fake IP to
    # steal another client's rate-limit budget (IP-bucket forgery).
    # Requires server.trusted_proxies=127.0.0.1 in merovingian.conf so
    # Merovingian reads this header for per-client rate limiting instead of
    # using the raw peer address (127.0.0.1 for all proxied traffic).
    RequestHeader unset X-Forwarded-For
    RequestHeader set X-Forwarded-For "expr=%{REMOTE_ADDR}"

    # ── Proxy routing ─────────────────────────────────────────────────────────
    # Exclude /.well-known/ from proxying so the Alias directives below are
    # reached.  Without the "!" exclusion, Apache forwards well-known requests
    # to Merovingian, which returns 404 because it does not own those paths.
    ProxyPass        "/.well-known/" "!"
    # /_matrix/federation/ and /_matrix/key/ go to the federation listener (8009)
    # so X-Matrix signature auth is applied, not the client access-token gate.
    ProxyPass        "/_matrix/federation/" "http://127.0.0.1:8009/_matrix/federation/"
    ProxyPassReverse "/_matrix/federation/" "http://127.0.0.1:8009/_matrix/federation/"
    # /_matrix/key/ exposes Merovingian's signing keys for remote servers to
    # verify federation request signatures and PDU event signatures.
    ProxyPass        "/_matrix/key/" "http://127.0.0.1:8009/_matrix/key/"
    ProxyPassReverse "/_matrix/key/" "http://127.0.0.1:8009/_matrix/key/"
    # Client-server API and media go to the client listener (8008).
    # Apache does not impose a default body-size limit, so no special handling
    # is needed for media uploads; if you add LimitRequestBody, set it to at
    # least the value of security.media.max_upload_size in merovingian.conf.
    ProxyPass        "/_matrix/client/" "http://127.0.0.1:8008/_matrix/client/"
    ProxyPassReverse "/_matrix/client/" "http://127.0.0.1:8008/_matrix/client/"

    # ── Static discovery files ────────────────────────────────────────────────
    # Served by Apache directly (see the shell snippet above) so they are
    # available even when Merovingian is restarting.  The ProxyPass "!" above
    # ensures requests for these paths are never forwarded to Merovingian.
    Alias "/.well-known/matrix/client" "/var/www/merovingian/.well-known/matrix/client"
    Alias "/.well-known/matrix/server" "/var/www/merovingian/.well-known/matrix/server"

    <Directory "/var/www/merovingian/.well-known/matrix">
        Require all granted
    </Directory>

    # ── Access control ────────────────────────────────────────────────────────
    # Default-deny: block every path so a misconfiguration never accidentally
    # exposes internal services.  Apache Location directives merge in document
    # order with later entries winning, so these specific allows must come AFTER
    # the "Require all denied" catch-all below.
    <Location "/">
        Require all denied
    </Location>

    <Location "/_matrix/client/">
        Require all granted
    </Location>

    <Location "/_matrix/federation/">
        Require all granted
    </Location>

    <Location "/_matrix/key/">
        Require all granted
    </Location>

    # /.well-known discovery — CORS is required here because browser clients
    # fetch these from a different origin (e.g. element.io or localhost).  This
    # is NOT a duplicate of Merovingian's CORS: Apache serves these files
    # directly from disk and never proxies them to Merovingian.
    <Location "/.well-known/matrix/client">
        Require all granted
        ForceType application/json
        Header always set Access-Control-Allow-Origin "*"
    </Location>

    <Location "/.well-known/matrix/server">
        Require all granted
        ForceType application/json
        Header always set Access-Control-Allow-Origin "*"
    </Location>
</VirtualHost>

# ── Native federation listener (port 8448) ────────────────────────────────────
# Handles direct federation connections from servers that do not follow the
# .well-known/matrix/server delegation to port 443.  Optional if all remote
# servers support .well-known discovery, but harmless to keep.
<VirtualHost *:8448>
    ServerName matrix.example.org

    # Same certificate as port 443.
    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/matrix.example.org/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/matrix.example.org/privkey.pem
    SSLProtocol           -all +TLSv1.2 +TLSv1.3

    # HSTS on the federation port prevents protocol-downgrade during server
    # discovery even when the remote server connects directly to port 8448.
    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"
    RequestHeader unset X-Forwarded-For
    RequestHeader set X-Forwarded-For "expr=%{REMOTE_ADDR}"

    # Only federation and key endpoints are reachable on port 8448.
    # The client-server API is never exposed here.
    ProxyPass        "/_matrix/federation/" "http://127.0.0.1:8009/_matrix/federation/"
    ProxyPassReverse "/_matrix/federation/" "http://127.0.0.1:8009/_matrix/federation/"
    ProxyPass        "/_matrix/key/" "http://127.0.0.1:8009/_matrix/key/"
    ProxyPassReverse "/_matrix/key/" "http://127.0.0.1:8009/_matrix/key/"

    # Default-deny: block everything not explicitly allowed above.
    <Location "/">
        Require all denied
    </Location>

    <Location "/_matrix/federation/">
        Require all granted
    </Location>

    <Location "/_matrix/key/">
        Require all granted
    </Location>
</VirtualHost>
```

### Caddy example

Caddy terminates TLS automatically with Let's Encrypt. Use a single
`matrix.example.org` site block that serves the well-known discovery
files inline and routes `/_matrix/` traffic to the loopback listeners.
Federation is reached either via the same `:443` block (with `/.well-known/
matrix/server` pointing at `:443`) or a separate `:8448` site.

```caddyfile
# ── Client-server API + delegated federation (port 443) ──────────────────────
# Caddy automatically obtains and renews a Let's Encrypt certificate for this
# site — no ssl_certificate directives are needed.  Caddy also adds HSTS,
# enforces modern TLS, and enables OCSP stapling by default.
matrix.example.org {

    # ── Matrix homeserver discovery (served inline, not proxied) ─────────────
    # These two well-known endpoints are required by the Matrix spec and are
    # served inline by Caddy so they remain available while Merovingian restarts.
    #
    # /.well-known/matrix/client: tells Matrix clients the base URL of the
    # homeserver.  Clients request this before logging in.  CORS is required
    # here because browser clients fetch it from a different origin
    # (e.g. element.io).  This is NOT a duplicate of Merovingian's CORS —
    # Caddy serves this path directly and never proxies it.
    @clientDiscovery path /.well-known/matrix/client
    handle_response @clientDiscovery {
        header Content-Type application/json
        header Access-Control-Allow-Origin "*"
        respond `{"m.homeserver":{"base_url":"https://matrix.example.org"}}` 200
    }

    # /.well-known/matrix/server: tells remote homeservers where to send
    # federation traffic.  "m.server":"matrix.example.org:443" delegates
    # federation to this site block so no separate port 8448 DNS entry is
    # required.  Remote servers fetch this during server discovery.
    @serverDiscovery path /.well-known/matrix/server
    handle_response @serverDiscovery {
        header Content-Type application/json
        header Access-Control-Allow-Origin "*"
        respond `{"m.server":"matrix.example.org:443"}` 200
    }

    # ── Federation and key-server API ─────────────────────────────────────────
    # Routes /_matrix/federation/ and /_matrix/key/ to the federation listener
    # (8009).  The split from port 8008 (client) is intentional: federation uses
    # X-Matrix signature auth, not Bearer tokens, and must not be routed through
    # the client-server access-token gate.
    @federation path /_matrix/federation/* /_matrix/key/*
    reverse_proxy @federation 127.0.0.1:8009

    # ── Client-server API and media ───────────────────────────────────────────
    # /_matrix/client/ handles login, registration, sync, messages, etc.
    # /_matrix/media/ must be listed alongside — without it media requests fall
    # through to the `respond 403` catch-all below, failing the browser CORS
    # preflight and breaking uploads, downloads, and user avatars.
    @client path /_matrix/client/* /_matrix/media/*
    reverse_proxy @client 127.0.0.1:8008

    # ── Catch-all: deny everything else ───────────────────────────────────────
    # Block any path not matched above so a misconfiguration never accidentally
    # exposes an internal service on this hostname.
    respond 403
}

# ── Native federation listener (port 8448) ────────────────────────────────────
# Handles direct federation connections from servers that do not follow the
# .well-known/matrix/server delegation to port 443.  Optional if all remote
# servers support .well-known discovery, but harmless to keep.  Only federation
# and key endpoints are forwarded; all other paths return 403.
matrix.example.org:8448 {
    @federation path /_matrix/federation/* /_matrix/key/*
    reverse_proxy @federation 127.0.0.1:8009
    respond 403
}
```

Caddy ships sane defaults for HSTS, modern TLS, and OCSP stapling, so no
extra `header` directives are required for those. CORS preflight is still
emitted by Merovingian; the `Access-Control-Allow-Origin` lines above are
only for the discovery JSON, which Caddy serves directly.

### Traefik example

Traefik v3 with the file provider. Use routers + services split by path
prefix; the static discovery files are served by a dedicated `file`
provider or a tiny HTTP backend.

```yaml
# traefik.yml (excerpt)
entryPoints:
  # Redirect all plain-HTTP traffic to HTTPS so no Matrix credentials are
  # sent in the clear.
  web:
    address: ":80"
    http:
      redirections:
        entryPoint:
          to: websecure
  # Main TLS entry point for client-server API and delegated federation.
  websecure:
    address: ":443"
  # Native Matrix federation port.  Required for servers that do not follow
  # .well-known/matrix/server delegation; optional but harmless otherwise.
  federation:
    address: ":8448"

# dynamic.yml
http:
  routers:
    # ── Client-server API + media ──────────────────────────────────────────────
    # Routes /_matrix/client/ and /_matrix/media/ to the client listener (8008).
    # Media must be included here: omitting it causes media requests to match no
    # router, return a CORS error, and break uploads, downloads, and avatars.
    client-server:
      rule: "Host(`matrix.example.org`) && (PathPrefix(`/_matrix/client/`) || PathPrefix(`/_matrix/media/`))"
      service: merovingian-client
      entryPoints: [websecure]
      tls: { certResolver: letsencrypt }

    # ── Federation + key API on port 443 (delegated) ──────────────────────────
    # Routes /_matrix/federation/ and /_matrix/key/ to the federation listener
    # (8009) so X-Matrix signature auth is applied, not the client access-token
    # gate on 8008.
    federation-443:
      rule: "Host(`matrix.example.org`) && (PathPrefix(`/_matrix/federation/`) || PathPrefix(`/_matrix/key/`))"
      service: merovingian-federation
      entryPoints: [websecure]
      tls: { certResolver: letsencrypt }

    # ── Native federation listener on port 8448 ───────────────────────────────
    # Accepts connections from servers that do not follow .well-known delegation.
    # The wildcard Host rule is safe here because only the federation entryPoint
    # binds port 8448 — no other services are reachable on this port.
    federation-8448:
      rule: "Host(`matrix.example.org`)"
      service: merovingian-federation
      entryPoints: [federation]
      tls: { certResolver: letsencrypt }

  services:
    # Client listener (8008): login, registration, sync, messages, media, keys.
    merovingian-client:
      loadBalancer:
        servers: [{ url: "http://127.0.0.1:8008" }]
    # Federation listener (8009): server-to-server PDU exchange, key fetching,
    # and X-Matrix signature authentication.
    merovingian-federation:
      loadBalancer:
        servers: [{ url: "http://127.0.0.1:8009" }]
```

`/.well-known/matrix/client` and `/server` are served by Merovingian
itself; with the wildcard CORS default no Traefik middleware is needed.
Do **not** add a `headers` middleware that sets `Access-Control-Allow-Origin` —
this would create duplicate header values that browsers reject.

### HAProxy example

HAProxy is the cheapest option for high-traffic deployments because it
does not buffer requests. The frontend terminates TLS; the backends
forward to the loopback listeners. ACLs route by path prefix so client
and federation traffic land on the correct backend.

```haproxy
# ── HTTPS frontend (port 443) ─────────────────────────────────────────────────
# Terminates TLS and routes to backends by path-prefix ACL.  ACLs are evaluated
# in order; the first matching use_backend rule wins.
frontend ft_https
    bind *:443 ssl crt /etc/haproxy/certs/matrix.example.org.pem alpn h2,http/1.1
    # Redirect any plain-HTTP request to HTTPS so no Matrix credentials are
    # sent in the clear (applies when the client connects on port 80 to the
    # same listener, e.g. if bind *:80 is also present).
    http-request redirect scheme https code 301 if !{ ssl_fc }

    # Path-prefix ACLs — determines which backend handles each request.
    acl is_client        path_beg /_matrix/client/
    acl is_media         path_beg /_matrix/media/
    acl is_federation    path_beg /_matrix/federation/
    acl is_key           path_beg /_matrix/key/

    # Client-server API and media both target the client listener (8008).
    use_backend bk_merovingian_client     if is_client || is_media
    # Federation and key-server API target the federation listener (8009) so
    # X-Matrix signature auth is applied, not the client access-token gate.
    use_backend bk_merovingian_federation if is_federation || is_key
    # /.well-known/matrix/{client,server} falls through to the client backend;
    # Merovingian does not own those paths but the client listener returns 404,
    # which is sufficient — serve them from a separate static backend if needed.
    use_backend bk_merovingian_client
    default_backend bk_merovingian_client

# ── Client-server backend ─────────────────────────────────────────────────────
# Serves the client-server API and media repository on port 8008.
backend bk_merovingian_client
    # Append the real client IP to X-Forwarded-For so Merovingian can use it
    # for per-client rate limiting.  Requires server.trusted_proxies=127.0.0.1
    # in merovingian.conf; without that, all clients share one rate-limit bucket.
    option forwardfor header X-Forwarded-For
    # Tell Merovingian the downstream connection arrived over HTTPS.
    http-request set-header X-Forwarded-Proto https
    server merovingian 127.0.0.1:8008 check

# ── Federation backend ────────────────────────────────────────────────────────
# Serves the server-to-server API and signing-key endpoints on port 8009.
backend bk_merovingian_federation
    option forwardfor header X-Forwarded-For
    http-request set-header X-Forwarded-Proto https
    server merovingian 127.0.0.1:8009 check

# ── Native federation listener (port 8448) ────────────────────────────────────
# Accepts direct federation connections from servers that do not follow the
# .well-known/matrix/server delegation to port 443.  Optional if all remote
# servers support .well-known discovery, but harmless to keep.  All traffic on
# this port is forwarded to the federation backend; the backend's Merovingian
# router returns 403 for any path that is not /_matrix/federation/ or
# /_matrix/key/.
frontend ft_federation_native
    bind *:8448 ssl crt /etc/haproxy/certs/matrix.example.org.pem alpn h2,http/1.1
    default_backend bk_merovingian_federation
```

HAProxy does not edit response headers unless told to; CORS preflight
therefore reaches the client as Merovingian emits it. Do **not** add
`http-response set-header Access-Control-Allow-Origin` to the backends —
this would create duplicate header values that browsers reject.

### Cloudflare example

Cloudflare's CDN terminates TLS and can route to an origin over HTTPS
or HTTP. The two gotchas are (a) Cloudflare adds its own
`Cf-Connecting-IP` and may strip `Authorization` if caching is on for
the route, and (b) `Origin` request headers are passed through, so
Merovingian's preflight handling still works.

```yaml
# Cloudflare dashboard or Terraform equivalent
record:
  - name: matrix
    type: A
    value: 203.0.113.10   # origin server public IP
    proxied: true

origin_rules:
  - name: "Matrix client + delegated federation (port 443)"
    condition: { hostname: "matrix.example.org" }
    destination: { port: 8008 }   # client traffic; the origin server's nginx then splits by path

  - name: "Federation native (port 8448)"
    condition: { hostname: "matrix.example.org", port: 8448 }
    destination: { port: 8009 }

ssl: full
```

For a Cloudflare-fronted deployment the cleanest split is to put nginx
in front of Merovingian on the origin box (the nginx example above
already handles that). Cloudflare then connects to nginx's `:443` over
HTTPS and forwards `Origin`, `Authorization`, and `Cf-Connecting-IP`
unmodified. Make sure the Cloudflare cache is **off** for `/_matrix/`
routes (set cache level to "Bypass" on the page rule) and that
"Authenticated Origin Pulls" is enabled so the origin only accepts
connections from Cloudflare.

### Smoke test for every proxy

After deploying, run this from the host that resolves
`matrix.example.org`. The 200 response MUST include the
`Access-Control-Allow-Origin` line; if it does not, the browser will
block the preflight and Element will fail to join a room.

```sh
curl -X OPTIONS \
    -H "Origin: vector://vector" \
    -H "Access-Control-Request-Method: GET" \
    -i https://matrix.example.org/_matrix/client/v3/versions
```

Expected response (200 + the CORS headers Merovingian emits):

```text
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS
Access-Control-Allow-Headers: authorization, content-type
Access-Control-Max-Age: 86400
Vary: Origin
```

Run the same preflight against a media endpoint. This is the check that catches a
missing `/_matrix/media/` proxy route — uploads, downloads, and avatars break
even when client traffic works:

```sh
curl -X OPTIONS \
    -H "Origin: vector://vector" \
    -H "Access-Control-Request-Method: GET" \
    -i https://matrix.example.org/_matrix/media/v3/config
```

A non-2xx here (typically `403` from a catch-all `location /`) is the classic
symptom: the browser reports "Response to preflight request doesn't pass access
control check: It does not have HTTP ok status" and the request fails with
`net::ERR_FAILED`. Merovingian itself answers this OPTIONS with `200` + CORS on
the client-server listener, so a failure is always a proxy routing gap.

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

### Inbound federation media serving

Locally uploaded media that is not quarantined or removed is automatically
available to remote homeservers through
`GET /_matrix/federation/v1/media/download/{mediaId}`. The endpoint is
authenticated with `X-Matrix` request signatures, bypasses the federation worker
because the worker has no access to the local media store, and returns a
`multipart/mixed` response per Matrix v1.19 (an empty JSON metadata part
followed by the media bytes). No extra configuration is required.

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
request rejections, locked/suspended-account request rejections, registration
policy denials) are written to the structured audit log. Query it through the
admin endpoint:

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
