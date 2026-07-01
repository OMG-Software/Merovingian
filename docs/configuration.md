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
- trust-safety transport enabled without a policy server URL
- non-HTTPS trust-safety policy server URL
- invalid trust-safety policy server timeout
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

**CORS preflight is handled by Merovingian itself (fully active since v0.5.28).**
The reverse proxy only needs to forward `Origin` and `Authorization` headers
unmodified. The proxy must **not** add `Access-Control-Allow-*` headers to
proxied responses. If both Merovingian and the proxy emit
`Access-Control-Allow-Origin`, the browser receives duplicate header values
(e.g. `*, *`), which the Fetch spec treats as invalid — browser clients will
show "Failed to connect" even though the server returns HTTP 200. The examples
below do **not** include proxy-level CORS headers. See
[CORS policy](#cors-policy) for the Merovingian-side config surface.

The `.well-known/matrix/client` and `.well-known/matrix/server` discovery
files are **served by the proxy itself** (not forwarded to Merovingian) in the
Apache and nginx examples, so those specific locations still need their own
`Access-Control-Allow-Origin` header — that is not a duplicate.

**Rate limiting requires `server.trusted_proxies`.**
When all traffic arrives through a reverse proxy, every request has the same
peer IP (`127.0.0.1`). Without `trusted_proxies`, all clients share one per-IP
rate-limit bucket — a single active Matrix client can exhaust the default
`90/60s` cap for everyone. Set `server.trusted_proxies=127.0.0.1` in
`merovingian.conf` so the rate limiter reads the real client IP from
`X-Forwarded-For`. The reverse proxy must set `X-Forwarded-For` to the direct
TCP peer IP it received; the examples below do this correctly. **Do not use
`$proxy_add_x_forwarded_for` (nginx) or omit the header (Apache):** both
allow a malicious client to forge a victim's IP and exhaust their rate-limit
bucket by injecting a fake `X-Forwarded-For` value into the request.

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

### nginx

This example terminates TLS in nginx, serves the discovery JSON directly,
and proxies Matrix traffic to Merovingian's loopback listeners. The `443`
server block handles client, media, and delegated federation traffic by path.
Media (`/_matrix/media/`) is served on the client-server listener (`8008`).

```nginx
# ── HTTP → HTTPS redirect ─────────────────────────────────────────────────────
# Reject plain-HTTP connections immediately so no Matrix credentials are ever
# sent in the clear.  All Matrix clients follow the 301 redirect to port 443.
server {
    listen 80;
    server_name matrix.example.org;
    return 301 https://$host$request_uri;
}

# ── Primary HTTPS block (client-server API + delegated federation) ────────────
# Handles: Matrix clients (/_matrix/client/), media (/_matrix/media/), and
# federation delegated from port 443 via /.well-known/matrix/server.  A
# separate block below covers native port 8448 for servers that do not follow
# .well-known delegation.
server {
    listen 443 ssl http2;
    server_name matrix.example.org;

    # ── TLS ───────────────────────────────────────────────────────────────────
    # Let's Encrypt certificate pair.  Merovingian binds to cleartext loopback
    # (127.0.0.1:8008/8009); all TLS is terminated here by nginx.
    ssl_certificate     /etc/letsencrypt/live/matrix.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/matrix.example.org/privkey.pem;
    # Disable TLS 1.0 and 1.1 — both have known practical attacks (BEAST,
    # POODLE).  Matrix spec requires TLS; older versions are non-compliant.
    ssl_protocols       TLSv1.2 TLSv1.3;

    # ── Security response headers ──────────────────────────────────────────────
    # HSTS: instructs browsers to enforce HTTPS for one year and opts the domain
    # into browser-bundled HSTS preload lists so first-visit connections are
    # also protected before any header has been seen.
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    # Prevent MIME-type sniffing.  Without this a browser could execute an
    # uploaded file served as "text/plain" if it detects executable content.
    add_header X-Content-Type-Options "nosniff" always;
    # Forbid this domain from being embedded in a frame on another origin,
    # protecting the login page against clickjacking attacks.
    add_header X-Frame-Options "DENY" always;
    # Do NOT add Access-Control-Allow-* here — Merovingian emits CORS headers on
    # all /_matrix/ responses.  Adding them at the proxy level creates duplicate
    # values (e.g. "*, *") that the Fetch spec treats as invalid; browsers reject
    # the response and clients show "Failed to connect" even on HTTP 200.

    # ── Matrix homeserver discovery (served by nginx, not proxied) ────────────
    # These two well-known endpoints are required by the Matrix spec.  nginx
    # serves them inline so they remain available while Merovingian restarts.
    #
    # /.well-known/matrix/client: tells Matrix clients (Element, Cinny, etc.)
    # the base URL of the homeserver.  Clients request this before logging in.
    location = /.well-known/matrix/client {
        default_type application/json;
        # CORS is required here — browser clients fetch this from a different
        # origin (e.g. element.io or localhost in development).  This header is
        # NOT a duplicate of Merovingian's CORS: nginx serves this path directly
        # and never proxies it to Merovingian.
        add_header Access-Control-Allow-Origin "*" always;
        return 200 '{"m.homeserver":{"base_url":"https://matrix.example.org"}}';
    }

    # /.well-known/matrix/server: tells remote homeservers where to send
    # federation traffic.  Pointing at port 443 here delegates federation to
    # this server block so no separate port 8448 DNS entry is required.
    location = /.well-known/matrix/server {
        default_type application/json;
        # Same CORS rationale as the client discovery above.
        add_header Access-Control-Allow-Origin "*" always;
        return 200 '{"m.server":"matrix.example.org:443"}';
    }

    # ── Federation API (server-to-server) ─────────────────────────────────────
    # Routes /_matrix/federation/ to Merovingian's dedicated federation listener
    # (8009).  The split between port 8008 (client) and 8009 (federation) is
    # intentional: federation uses X-Matrix signature auth, not Bearer tokens,
    # and must never be routed through the client-server access-token gate.
    location /_matrix/federation/ {
        proxy_pass http://127.0.0.1:8009;
        # Pass the original Host header so Merovingian knows the server name
        # when constructing federation responses and verifying signatures.
        proxy_set_header Host $host;
        # Tell Merovingian the downstream connection arrived over HTTPS.
        # Without this, code inspecting the forwarded protocol sees cleartext.
        proxy_set_header X-Forwarded-Proto https;
        # Pass the real client IP for per-client rate limiting.  Use $remote_addr
        # (the IP nginx received the TCP connection from) — NOT
        # $proxy_add_x_forwarded_for, which appends to whatever the client sent
        # and allows a malicious client to forge a victim's rate-limit bucket.
        # Effective only when server.trusted_proxies=127.0.0.1 is set in
        # merovingian.conf; without that setting all traffic shares one bucket.
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    # ── Server key API ────────────────────────────────────────────────────────
    # Routes /_matrix/key/ to the federation listener.  Remote servers fetch
    # these endpoints to obtain and verify Merovingian's Ed25519 signing keys
    # when authenticating incoming federation requests and PDUs.
    location /_matrix/key/ {
        proxy_pass http://127.0.0.1:8009;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    # ── Client-server API ─────────────────────────────────────────────────────
    # Routes all Matrix client traffic to the client listener (8008).  Covers
    # login, registration, sync, sending messages, invites, device keys, etc.
    location /_matrix/client/ {
        proxy_pass http://127.0.0.1:8008;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
    }

    # ── Media repository ──────────────────────────────────────────────────────
    # Media (/_matrix/media/) is served on the client listener (8008) and
    # requires its own location block for two reasons:
    # (1) Without this block, /_matrix/media/ falls through to `location /`
    #     below (403).  The browser CORS preflight then fails with "preflight
    #     does not have HTTP ok status" — uploads, downloads, and user avatars
    #     all break even though all other client traffic works correctly.
    # (2) nginx's default client_max_body_size is 1 MiB.  File uploads silently
    #     return 413 before reaching Merovingian.  Set this to match
    #     security.media.max_upload_size in merovingian.conf (default 50 MiB).
    location /_matrix/media/ {
        proxy_pass http://127.0.0.1:8008;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        client_max_body_size 50m;
    }

    # ── Catch-all: deny everything else ───────────────────────────────────────
    # Explicitly block any path not matched above so a misconfiguration never
    # accidentally exposes an internal service on this hostname.
    location / {
        return 403;
    }
}

# ── Native federation listener (port 8448) ────────────────────────────────────
# Some homeservers connect directly to port 8448 rather than following the
# .well-known/matrix/server delegation.  This block covers those servers.
# If your /.well-known/matrix/server points at port 443 and you do not need
# backwards compatibility with non-.well-known-aware servers, this block is
# optional but harmless to keep.
server {
    listen 8448 ssl http2;
    server_name matrix.example.org;

    ssl_certificate     /etc/letsencrypt/live/matrix.example.org/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/matrix.example.org/privkey.pem;
    ssl_protocols       TLSv1.2 TLSv1.3;

    # Only federation and key endpoints are reachable on port 8448.
    # The client-server API is never exposed here.
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

### Caddy

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

### Traefik

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

### HAProxy

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

### Cloudflare

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
in front of Merovingian on the origin box (the nginx section above
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

## Secrets and at-rest encryption

A 256-bit master key can be configured to encrypt sensitive material that is
persisted to the database. The file must contain exactly 32 raw bytes and should
be protected with owner-only, non-executable permissions, outside web roots:

```text
security.secrets.master_key_file=/etc/merovingian/master.key
```

When this key is present, the Ed25519 server signing secret is encrypted at rest
with `secret_box` (`secretbox:v1:...`) before being stored in the database. If no
master key is configured the secret is stored as a legacy plaintext base64 value
for backward compatibility and a one-time diagnostic warns the operator. Rotating
the signing key after enabling the master key will re-encrypt the active secret
under the new at-rest format.

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
can re-run secret-file metadata checks. The token is hashed with Argon2id at load
time and only the hash is retained in process memory; the plaintext is zeroised
after hashing.

Successful public registration creates a normal user only. Admin users must be
created through the explicit operator bootstrap path, not by being the first
public registrant.

## Token expiry policy

Access and refresh tokens expire server-side. The enforced lifetimes are
configurable in milliseconds; `0` disables expiry for that token kind (treated
as no expiry):

```text
security.access_token_lifetime_ms=3600000
security.refresh_token_lifetime_ms=2592000000
```

Defaults are 1 hour for access tokens and 30 days for refresh tokens. The
`expires_in_ms` value advertised by `/login` and `/refresh` reads from
`security.access_token_lifetime_ms`, so the advertised TTL matches the
enforced one. A token past its TTL is rejected even when its session is not
revoked — the request path returns `401 M_UNKNOWN_TOKEN` and the audit log
records `access_token.rejected` with reason `token expired`, forcing the
client to refresh or re-login. Existing rows written without an expiry (empty
`expires_at`, or `nullopt` in memory) remain valid, so legacy sessions are not
invalidated by the upgrade.

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

## Federation join timeout and parallelism

Joining a remote room runs the `make_join`/`send_join` dance against the resident
server(s). A large room on a slow resident server (e.g. matrix.org) can take
longer than the 60s general `security.federation.remote_timeout`, surfacing as
`502 make_join failed: timeout`. Two keys give that dance a separate,
extendable budget and parallelise candidate probes:

```text
security.federation.join_timeout=180s
security.federation.join_parallelism=8
```

| Key | Type | Default | Reload | Notes |
|-----|------|---------|--------|-------|
| `security.federation.join_timeout` | duration | `180s` | reloadable (`requires_restart=false`) | Budget for `make_join`/`send_join`/`make_leave`/`send_leave`. Separate from `remote_timeout` (60s), which still governs all other federation calls. |
| `security.federation.join_parallelism` | unsigned int | `8` | reloadable (`requires_restart=false`) | Cap on concurrent `make_join` candidate probes (first success wins; `send_join` targets the winner) and concurrent inbound `/send` sender-key resolution. Must be `>= 1`; `0` is rejected at validation. |

`join_timeout` accepts the same positive bounded duration suffixes (`s`, `m`)
as `remote_timeout`; `0s` is rejected.

## Federation worker (out-of-process)

When a user joins a large federated room, the inbound PDU verification, state
resolution, and membership state machine can saturate the main thread pool and
make all connected clients unresponsive. The federation worker moves that work
into a dedicated child process with its own thread pool.

The `merovingian-fed-worker` process is **mandatory** when `security.federation.enabled=true`
(the default). Startup fails fatally if the worker binary cannot be launched.
There is no in-process fallback; requests return `503` while a crashed worker
is restarting.

```text
federation.worker.threads=4
federation.worker.shards=2
federation.worker.binary=/usr/libexec/merovingian/merovingian-fed-worker
federation.worker.request_timeout_seconds=120
```

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `federation.worker.threads` | unsigned int | `4` | Thread pool size inside each `merovingian-fed-worker` process. Increase for deployments that federate with many rooms simultaneously. |
| `federation.worker.shards` | unsigned int | `1` | Number of independent federation worker processes. Requests are routed by `fnv1a_32(room_id) % shards`; non-room endpoints (key queries, profile queries, etc.) go to shard 0. Must be greater than 0. |
| `federation.worker.binary` | string | compile-time default | Absolute path to the `merovingian-fed-worker` binary. Empty means `$libexecdir/merovingian/merovingian-fed-worker` (baked in as `MEROVINGIAN_LIBEXECDIR` at build time). |
| `federation.worker.request_timeout_seconds` | unsigned int | `120` | Per-request IPC timeout in seconds. A federation request that takes longer than this returns a 504 to the remote server. |

The worker communicates with the main process over an `AF_UNIX SOCK_STREAM`
socket pair inherited at spawn. All frames are encrypted with an ephemeral
`crypto_kx` key exchange and `crypto_secretstream_xchacha20poly1305` AEAD —
no sensitive material is transmitted in plaintext. The server signing key is
never forwarded; the worker reads it from the same database. Client access
tokens are stripped from every request before forwarding.

If the worker crashes, `WorkerSupervisor` restarts it with exponential
back-off (1 s, 2 s, 4 s, 8 s, then capped at 30 s). When
`fallback_in_process=true` the main process handles federation directly while
the worker is recovering.

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

`security.media.allowed_mime_types` is a comma-separated list of MIME types the
server accepts without quarantining. The default list is:

```text
image/png,image/jpeg,image/gif,text/plain,application/pdf,application/octet-stream
```

`application/octet-stream` is included because encrypted-room attachments are
uploaded by clients as opaque ciphertext; without it, every encrypted image or
file is quarantined and later downloads return 451. Operators who want a stricter
policy can override the list explicitly.

Two `security.media.*` keys are not fully wired end to end yet:

- `security.media.enable_av_scanner` is parsed, but it does **not** configure
  or launch an antivirus engine. It only changes how the media policy treats a
  scanner verdict supplied by an upstream caller.
- `security.media.remote_fetch_timeout` is parsed and validated, but the live
  remote-fetch path still uses hard-coded discovery and outbound HTTP timeouts.

## Trust and safety policy transport

The trust-safety transport is opt-in and fail-closed by default:

```text
security.trust_safety.enabled=true
security.trust_safety.policy_server_url=https://policy.example.org/check
security.trust_safety.policy_server_timeout=5s
security.trust_safety.policy_server_allow_without_result=false
```

When enabled, Merovingian POSTs a small JSON decision request to the configured
HTTPS endpoint for registration, room creation, inbound federation, and media
download checks. The request includes:

- `surface`
- `entity`
- `server_name`

The response body is expected to be JSON with at least:

- `action`
  Allowed values: `allow`, `deny`, `quarantine`, `lock_account`,
  `suspend_account`.
- `rule_id`
  Optional but recommended for audit correlation.
- `summary`
  Optional operator-facing summary.
- `reason`
  Optional detailed reason string.

If the policy server is unreachable, returns a non-2xx status, omits a usable
decision, or sends malformed JSON, the guarded workflow is rejected unless
`security.trust_safety.policy_server_allow_without_result=true`.

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
`docs/todos/production-milestone.md` pass. Do not publish them as a production release
while runtime listeners, durable storage, federation verification, or hardening
checks remain incomplete.
| `secret redaction policy` | Enabled by validated logging defaults |

Unknown values are not success claims. They mark work that still requires platform-specific runtime probes or sandbox setup.

## CORS policy

CORS preflight is emitted by Merovingian itself (since 0.4.60). The
relevant config keys live under `server.cors.*`:

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `server.cors.allowed_origins` | string list (CSV) | `*` | Origins allowed to make cross-origin requests. Wildcard `*` is the safe default for Matrix because clients authenticate with `Authorization: Bearer` tokens, not browser cookies. Use an explicit list when embedding web clients in a mixed-trust context. |
| `server.cors.allow_methods` | string | `GET, POST, PUT, DELETE, OPTIONS` | Advertised in the preflight `Access-Control-Allow-Methods` header. |
| `server.cors.allow_headers` | string | `authorization, content-type` | Advertised in the preflight `Access-Control-Allow-Headers` header. This is the set Matrix clients actually send. |
| `server.cors.allow_credentials` | bool | `false` | When `true`, sets `Access-Control-Allow-Credentials: true`. The CORS spec forbids combining this with a wildcard `*` origin; the config parser rejects the combination. |
| `server.cors.max_age` | non-negative integer | `86400` | How long, in seconds, the browser may cache the preflight result. 24h by default; reduce to 0 to disable caching. |

The reverse proxy in front of Merovingian must **not** add
`Access-Control-Allow-*` headers to proxied `/_matrix/` responses —
Merovingian already emits them. If the proxy also emits
`Access-Control-Allow-Origin`, the browser receives multiple values for the
same header (e.g. `*, *`). The Fetch spec treats this as invalid; the browser
rejects the response and browser clients show "Failed to connect" even though
the server returns HTTP 200.

Remove any `add_header Access-Control-*` / `Header always set Access-Control-*`
directives from your proxy config and let Merovingian be the sole source of CORS
headers for `/_matrix/` traffic.

CORS is not hot-reloadable: a change to any `server.cors.*` key requires
a server restart. This matches how other HTTP-behaviour keys behave; see
[Reloadability policy](#reloadability-policy) for the full set of
reloadable keys.

## Client rate limits (0.5.0)

The wall-clock rate limiter uses two operator-supplied maps keyed by
request target prefix, plus a per-IP fallback. Every entry takes the
form `<max_requests>/<window_seconds>s`; the parser rejects a zero-window
or zero-cap policy at startup rather than letting the engine loop.

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `client_rate_limits.per_ip.<target>` | `<N>/<Ws>s` | unset | Per-IP cap for any request whose target starts with `<target>`. The longest matching prefix wins. |
| `client_rate_limits.per_user.<target>` | `<N>/<Ws>s` | unset | Per-user cap (keyed by access token) for the same target. Empty by default; populate `/_matrix/client/v3/login` to mitigate credential-stuffing. |
| `client_rate_limits.default_per_ip` | `<N>/<Ws>s` | `90/60s` | Fallback for targets not matched by any `per_ip.*` entry. |

The map keys are dotted to support target prefixes that themselves
contain slashes — e.g.
`client_rate_limits.per_ip./_matrix/client/v3/login=20/60s`.

Rate-limit changes are not hot-reloadable: the engine is built once at
`start_client_server` and stored in the runtime. Restart the server for
changes to take effect.

### Rate limiting behind a reverse proxy

Per-IP limits key on the **effective client IP** — which is the raw TCP peer
address unless `server.trusted_proxies` is configured. Behind a reverse proxy
the raw peer is always the proxy (`127.0.0.1`), collapsing every downstream
client into one shared bucket.

**Symptom:** a single Cinny or Element session doing rapid-fire sync
(`timeout=0`) generates ~60 requests/min, exhausting the default `90/60s` cap
for all clients simultaneously. Subsequent requests — including the client's
own `GET /_matrix/client/versions` health-check — receive `429 Too Many
Requests`, and the client shows "Failed to connect" or "Server unavailable".

**Fix:** set `server.trusted_proxies=127.0.0.1` in `merovingian.conf` (adjust
the IP if your proxy does not bind to loopback). Merovingian then reads the
leftmost `X-Forwarded-For` value as the effective IP, giving each downstream
client its own isolated bucket. The proxy must overwrite `X-Forwarded-For`
with the direct peer IP it received — not append to whatever the client sent.
See [Reverse proxy examples](#reverse-proxy-examples) for the correct
per-proxy directives.

See `docs/log-filtering.md` for the operator recipe, including the
default values for `/login`, `/register`, keys, devices, media, and
federation.

## Log module overrides (0.5.0)

The process-wide `SingleLog` consumes a per-module level map at startup.
Each entry names a module and one of `trace`, `debug`, `info`, `notice`,
`warning`, `error`, `critical`, `off` (case-folded). The special key
`*` sets the default level every other module sees.

| Key | Type | Default | Notes |
|-----|------|---------|-------|
| `log_modules.<module>` | log level | unset | Per-module override; takes the value's level at startup. |
| `log_modules.*` | log level | unset | Sets the default level for modules not explicitly named. |

Log level changes are not hot-reloadable: the bootstrap runs once at
`start_client_server`. Restart the server for changes to take effect.

See `docs/log-filtering.md` for the operator recipe and the full set of
module names.

## Current keys

See `config/merovingian.conf.example` for the complete accepted key list.
