# Configuration

The bootstrap configuration uses a conservative dependency-free `key=value` format.

This format is intentionally narrow while the runtime is still being built. It provides a checked operator-facing configuration path without adding a YAML, TOML, or JSON dependency before dependency review is complete.
The checked-in example config includes explanatory full-line comments for each
operator-facing section. Keep comments on their own lines: the parser ignores
lines beginning with `#`, but values should remain plain `key=value` entries.

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

Plan a configuration reload without applying it:

```bash
./build/src/merovingian-server --plan-config-reload current.conf next.conf
```

Provision the first administrator through an explicit operator startup action:

```bash
./build/src/merovingian-server --config config/merovingian.conf.example \
  --bootstrap-admin alice \
  --bootstrap-admin-password-file /run/merovingian/bootstrap-admin-password
```

The password file is read as a single line with CRLF/LF line endings trimmed.
The account is created through the same persisted admin-user path used by tests,
before listeners are bound. Public Matrix registration never grants admin
privileges implicitly.

## Format rules

- One `key=value` pair per line.
- Blank lines are ignored.
- Lines beginning with `#` are ignored.
- Inline trailing comments after values are not supported.
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
- TLS listener without certificate or private-key paths
- missing configured TLS certificate or private-key file
- unsafe configured TLS certificate or private-key file permissions
- open registration without token requirement
- token-protected registration without a registration token file
- disabled default encryption for new rooms
- disabled direct-message encryption requirement
- invalid federation default policy
- deny-by-default federation without allowed servers
- malformed federation allowed server entry
- malformed federation denied server entry
- disabled federation TLS validation
- disabled federation JSON signature verification
- missing private or loopback federation deny ranges
- invalid federation transaction size
- invalid federation remote timeout
- invalid media upload size
- disabled private-IP blocking for remote media fetches
- invalid media remote fetch timeout
- disabled sandboxed media decoding
- disabled token or event-content log redaction

## Exit codes

Bootstrap exits with explicit status codes:

| Code | Meaning |
| ---: | --- |
| 0 | Success, help, version output, successful config check, or successful reload plan |
| 64 | Usage error |
| 66 | Config file open/read failure |
| 78 | Config parse failure |
| 79 | Config validation failure |

## Listener exposure policy

The defaults bind both client and federation listeners to loopback with TLS
disabled. This supports a reverse-proxy deployment model while avoiding
accidental public cleartext exposure. The client listener defaults to
`127.0.0.1:8008`; the internal federation listener defaults to
`127.0.0.1:8009` so Apache, nginx, or another reverse proxy can own the public
Matrix federation port `8448`.

A listener with `tls=false` must bind to one of:

- `127.0.0.1`
- `localhost`
- `::1`
- `[::1]`

A non-loopback listener must set `tls=true`.

When a listener sets `tls=true`, it must also set both key-material paths:

```text
listeners.client.tls=true
listeners.client.tls_certificate_file=/etc/merovingian/client.pem
listeners.client.tls_private_key_file=/etc/merovingian/client.key
listeners.federation.tls=true
listeners.federation.tls_certificate_file=/etc/merovingian/federation.pem
listeners.federation.tls_private_key_file=/etc/merovingian/federation.key
```

Configured TLS certificate files must exist as regular non-executable files
without group or other write permission. Configured TLS private-key files must
exist as regular owner-only non-executable secret files. Startup loads the
certificate chain and private key before binding the listener, verifies that the
private key matches the certificate, and fails closed if OpenSSL rejects either
file.

## Reverse proxy examples

Running Merovingian behind a reverse proxy is the preferred deployment model.
Terminate public TLS at nginx, Apache httpd, Caddy, or another proxy, and keep
Merovingian bound to loopback cleartext behind it. The recommended deployment
shape is:

```text
listeners.client.bind=127.0.0.1:8008
listeners.client.tls=false
listeners.federation.bind=127.0.0.1:8009
listeners.federation.tls=false
```

Serve `/.well-known/matrix/client` from the proxy. Merovingian does not need to
own that static discovery response:

```json
{
  "m.homeserver": {
    "base_url": "https://matrix.example.org"
  }
}
```

Replace `matrix.example.org` with your `server.public_baseurl` value throughout
the examples below.

If you publish `/.well-known/matrix/server` and delegate federation to
`matrix.example.org:443`, the proxy on `443` MUST split routes by path:

- `/_matrix/client/` -> `127.0.0.1:8008`
- `/_matrix/federation/` -> `127.0.0.1:8009`
- `/_matrix/key/` -> `127.0.0.1:8009`

Forwarding every `/_matrix/` request on `443` to the client listener will break
federation authentication because remote homeservers will hit the client-server
access-token gate instead of the federation router.

**Apache** serves these discovery files from static files — create them once
before reloading:

```sh
mkdir -p /var/www/merovingian/.well-known/matrix
printf '{"m.homeserver":{"base_url":"https://matrix.example.org"}}' \
    > /var/www/merovingian/.well-known/matrix/client
printf '{"m.server":"matrix.example.org:443"}' \
    > /var/www/merovingian/.well-known/matrix/server
```

**nginx** returns the responses inline from the config; no files are needed.

### Apache httpd

This example assumes `mod_ssl`, `mod_headers`, `mod_proxy`,
`mod_proxy_http`, and `mod_rewrite` are enabled. Apache owns public ports `443`
and `8448`; Merovingian listens only on loopback ports `8008` and `8009`. The
`443` vhost handles both client and delegated federation traffic by path.

```apache
Listen 8448

<VirtualHost *:80>
    ServerName matrix.example.org
    RewriteEngine On
    RewriteRule ^ https://%{SERVER_NAME}%{REQUEST_URI} [END,NE,R=permanent]
</VirtualHost>

<VirtualHost *:443>
    ServerName matrix.example.org

    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/matrix.example.org/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/matrix.example.org/privkey.pem
    SSLProtocol           -all +TLSv1.2 +TLSv1.3

    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"
    Header always set X-Content-Type-Options "nosniff"
    Header always set X-Frame-Options "DENY"
    Header always set Access-Control-Allow-Origin "*"
    Header always set Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS"
    Header always set Access-Control-Allow-Headers "X-Requested-With, Content-Type, Authorization, Date"

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"

    # Exclude /.well-known/ from proxying so the Alias below is reached.
    # Without this, Apache forwards /.well-known/ requests to Merovingian.
    ProxyPass        "/.well-known/" "!"
    ProxyPass        "/_matrix/federation/" "http://127.0.0.1:8009/_matrix/federation/"
    ProxyPassReverse "/_matrix/federation/" "http://127.0.0.1:8009/_matrix/federation/"
    ProxyPass        "/_matrix/key/" "http://127.0.0.1:8009/_matrix/key/"
    ProxyPassReverse "/_matrix/key/" "http://127.0.0.1:8009/_matrix/key/"
    ProxyPass        "/_matrix/client/" "http://127.0.0.1:8008/_matrix/client/"
    ProxyPassReverse "/_matrix/client/" "http://127.0.0.1:8008/_matrix/client/"

    Alias "/.well-known/matrix/client" "/var/www/merovingian/.well-known/matrix/client"
    Alias "/.well-known/matrix/server" "/var/www/merovingian/.well-known/matrix/server"

    <Directory "/var/www/merovingian/.well-known/matrix">
        Require all granted
    </Directory>

    # Deny everything by default. Specific allows below must come AFTER this
    # block — Apache Location merging uses document order; later = wins.
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

<VirtualHost *:8448>
    ServerName matrix.example.org

    SSLEngine on
    SSLCertificateFile    /etc/letsencrypt/live/matrix.example.org/fullchain.pem
    SSLCertificateKeyFile /etc/letsencrypt/live/matrix.example.org/privkey.pem
    SSLProtocol           -all +TLSv1.2 +TLSv1.3

    Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains; preload"

    ProxyPreserveHost On
    RequestHeader set X-Forwarded-Proto "https"

    ProxyPass        "/_matrix/federation/" "http://127.0.0.1:8009/_matrix/federation/"
    ProxyPassReverse "/_matrix/federation/" "http://127.0.0.1:8009/_matrix/federation/"
    ProxyPass        "/_matrix/key/" "http://127.0.0.1:8009/_matrix/key/"
    ProxyPassReverse "/_matrix/key/" "http://127.0.0.1:8009/_matrix/key/"

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

### nginx

This example terminates TLS in nginx, serves the discovery JSON directly,
and proxies Matrix traffic to Merovingian's loopback listeners. The `443`
server block handles both client and delegated federation traffic by path.

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
    add_header Access-Control-Allow-Origin "*" always;
    add_header Access-Control-Allow-Methods "GET, POST, PUT, DELETE, OPTIONS" always;
    add_header Access-Control-Allow-Headers "X-Requested-With, Content-Type, Authorization, Date" always;

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
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /_matrix/key/ {
        proxy_pass http://127.0.0.1:8009;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /_matrix/client/ {
        proxy_pass http://127.0.0.1:8008;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location / {
        return 403;
    }
}

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
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location /_matrix/key/ {
        proxy_pass http://127.0.0.1:8009;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }

    location / {
        return 403;
    }
}
```

## Registration Token Policy

Public registration is disabled by default. If it is enabled, startup requires
token protection and a token file:

```text
security.registration.enabled=true
security.registration.require_token=true
security.registration.token_file=/etc/merovingian/registration-token
```

The token file is read by the registration path and should contain the
registration token on its first line. Treat it as a secret: owner-only,
non-executable, outside web roots, and rotated whenever it may have been
shared too broadly. Changing the token-file path requires a restart so startup
can re-run secret-file metadata checks.

Successful public registration creates a normal user only. Admin users must be
created through the explicit operator bootstrap path, not by being the first
public registrant.

## Federation exposure policy

Federation can be disabled globally:

```text
security.federation.enabled=false
```

When federation is enabled, `security.federation.default_policy` controls the default decision for remote servers:

```text
security.federation.default_policy=allow
security.federation.default_policy=deny
```

`security.federation.denied_servers` blocks listed remote servers regardless of the default policy or allow list:

```text
security.federation.denied_servers=bad.example,abuse.example
```

`security.federation.allowed_servers` is used when the default policy is `deny`; only listed servers can federate, unless they are also denied:

```text
security.federation.default_policy=deny
security.federation.allowed_servers=matrix.org,example.net
```

Deny-by-default federation requires a non-empty `allowed_servers` list while federation is enabled. Server list entries must be bounded server-name strings and may contain ASCII letters, digits, dots, hyphens, and port separators.

`security.federation.deny_ip_ranges` remains separate from server-name policy and is used for private or loopback network-range blocking.

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
security.media.remote_fetch_timeout=30s
```

Values such as `0s`, `30`, `30ms`, and `forever` are rejected.

Remote media fetching is opt-in. `security.media.remote_fetch_enabled=false`
is the default; setting it to `true` enables the repository remote-ingest
boundary, while private and loopback resolved addresses remain blocked when
`security.media.block_private_ip_fetches=true`.

## Reloadability policy

Configuration parsing and validation are restart-safe today. Runtime hot reload is a Phase 2 boundary, not a completed control plane. The server now classifies keys by reload policy so later SIGHUP or admin-socket reload work can apply reloadable settings without treating every config change as a whole homeserver restart.

Reload planning compares validated current and next configs and reports how many changes are reloadable versus restart-required. Planning is analysis-only until the live reload control path exists. A successful plan exits with status `0`, even when the action says a restart is required, because the planning operation itself succeeded.

Example reloadable output:

```text
Reload plan: changes=1 reloadable=1 restart_required=0
Reload action: reloadable
security.federation.remote_timeout=reloadable
```

Example restart-required output:

```text
Reload plan: changes=1 reloadable=0 restart_required=1
Reload action: restart required
server.name=restart_required
```

Example no-op output:

```text
Reload plan: changes=0 reloadable=0 restart_required=0
Reload action: no changes
```

| Key or key group | Policy |
| --- | --- |
| `server.name` | Restart required |
| `database.uri_file` | Restart required |
| `database.role` | Restart required |
| `listeners.*.tls_certificate_file` | Restart required |
| `listeners.*.tls_private_key_file` | Restart required |
| `database.pool_size` | Reloadable |
| Other `listeners.*` keys | Reloadable |
| `security.registration.*` | Reloadable |
| `security.encryption.*` | Reloadable |
| `security.federation.*` | Reloadable |
| `security.media.*` | Reloadable |
| `security.logging.*` | Reloadable |

Restart-required keys affect stable process identity or secret source selection. Reloadable keys are runtime policy or limit values that should be applied through the future reload path without a full homeserver restart.

## Runtime config snapshot

The runtime config snapshot owns the currently validated in-memory config and can apply a candidate config only when the reload plan has no restart-required changes.

Application outcomes are:

| Outcome | Meaning |
| --- | --- |
| `unchanged` | Candidate config matches the current runtime config. |
| `applied` | Candidate config changed only reloadable keys and replaced the in-memory snapshot. |
| `restart_required` | Candidate config changed at least one restart-required key and was not applied. |

The snapshot is an internal foundation for future live reload. It is not yet connected to SIGHUP, an admin socket, or any external control API.

## Startup hardening self-check

Startup logs a fixed checklist of hardening signals. Phase 2 exposes the checklist shape and intentionally reports `unknown` where the runtime probe has not been implemented yet.

| Check | Current signal source |
| --- | --- |
| `compiler hardening` | Placeholder, currently `unknown` |
| `linker hardening` | Placeholder, currently `unknown` |
| `PIE` | Compile-time macro when available, otherwise `unknown` |
| `RELRO` | Placeholder, currently `unknown` |
| `stack protector` | Compile-time macro when available, otherwise `unknown` |
| `FORTIFY_SOURCE` | Compile-time macro when available, otherwise `unknown` |
| `seccomp` | Placeholder, currently `unknown` |
| `pledge/unveil` | Placeholder, currently `unknown` |
| `capsicum` | Placeholder, currently `unknown` |
| `privilege drop` | Placeholder, currently `unknown` |
| `filesystem restrictions` | Placeholder, currently `unknown` |
| `core dump policy` | Placeholder, currently `unknown` |

## Production packaging

Production package assets are intentionally separated from the bootstrap config:

- `packaging/systemd/merovingian.service`
- `packaging/openrc/merovingian`
- `packaging/rc.d/merovingian`
- `Dockerfile`

These assets are deployment scaffolds until the production gates in
`docs/01-progress-tracker.md` pass. Do not publish them as a production release
while runtime listeners, durable storage, federation verification, or hardening
checks remain incomplete.
| `secret redaction policy` | Enabled by validated logging defaults |

Unknown values are not success claims. They mark work that still requires platform-specific runtime probes or sandbox setup.

## Current keys

See `config/merovingian.conf.example` for the complete accepted key list.
