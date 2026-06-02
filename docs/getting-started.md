# Getting Started

This guide covers building Merovingian, writing a minimal config, running
the server for the first time, creating an admin account, and connecting a
Matrix client.

## 1. Build

```sh
# Install dependencies
sh scripts/setup-dev-env.sh

# Build (Linux)
python build.py linux

# Or on WSL:
python build.py wsl
```

`build.py` configures, compiles, and runs tests in one step. It delegates to
the shell scripts in `scripts/` (see [dev-environment.md](dev-environment.md)
for all targets and options).

For manual Meson control:

```sh
meson setup build --wrap-mode=forcefallback
meson compile -C build
meson test -C build
```

The server binary is at `build/src/merovingian-server`.

## 2. Write a minimal config

Copy the annotated example and edit the three fields that must match your
host:

```sh
cp config/merovingian.conf.example /etc/merovingian/merovingian.conf
```

Minimum changes required:

```ini
# The Matrix server name used in every user ID, e.g. @alice:example.org
server.name=example.org

# The HTTPS URL clients use to reach the homeserver
server.public_baseurl=https://matrix.example.org

# For a quick start, switch to SQLite (no PostgreSQL needed):
#   comment out the three PostgreSQL keys and uncomment the two below
#database.backend=sqlite
#database.sqlite_path=/var/lib/merovingian/merovingian.sqlite3
```

### SQLite quick start (development / evaluation)

Comment out the PostgreSQL block and uncomment the SQLite block:

```ini
# Remove or comment out:
# database.uri_file=...
# database.role=...
# database.pool_size=...

# Uncomment:
database.backend=sqlite
database.sqlite_path=/var/lib/merovingian/merovingian.sqlite3
```

Only **one** `database.backend` line may appear in the config — duplicates
are rejected at startup.

### PostgreSQL (production)

Keep the PostgreSQL block and write the connection URI to a secret file:

```sh
echo "postgresql://merovingian:secret@localhost/merovingian" \
  | sudo tee /etc/merovingian/db-uri
sudo chmod 600 /etc/merovingian/db-uri
```

## 3. Validate the config before starting

```sh
merovingian-server --dry-run --config /etc/merovingian/merovingian.conf
```

A clean run prints the resolved settings and exits 0. Any rejected key is
reported with a clear message before the server starts.

## 4. Start the server

```sh
merovingian-server --config /etc/merovingian/merovingian.conf
```

The server listens on the ports defined by `listeners.client.bind` (default
`127.0.0.1:8008`) and `listeners.federation.bind` (default
`127.0.0.1:8009`). Running Merovingian behind a reverse proxy (nginx, Apache,
Caddy) is the preferred way to deploy it; let the proxy handle public TLS and
keep Merovingian on loopback listeners behind it. If the proxy exposes
federation on `443` via
`/.well-known/matrix/server`, route `/_matrix/client/` to `8008` and route
`/_matrix/federation/` plus `/_matrix/key/` to `8009`.

CORS preflight is now handled by Merovingian itself (since 0.4.60). The proxy
only needs to forward `Origin` and `Authorization` headers unmodified; it does
**not** need to synthesise `Access-Control-Allow-*` headers. See
[Reverse proxy examples](configuration.md#reverse-proxy-examples) for nginx,
Apache, Caddy, Traefik, HAProxy, and Cloudflare configs.

Confirm it is reachable:

```sh
curl -s http://127.0.0.1:8008/_matrix/client/versions
# → {"versions":[...],"unstable_features":{}}
```

## 5. Create the first admin account

Use `--bootstrap-admin` to create an admin user before opening registration.
The password is read from a file so it never appears in the process list.

```sh
# Write the password to a temp file (600 permissions)
echo "CorrectHorse7!" > /tmp/admin-pw
chmod 600 /tmp/admin-pw

merovingian-server \
  --config /etc/merovingian/merovingian.conf \
  --bootstrap-admin alice \
  --bootstrap-admin-password-file /tmp/admin-pw

rm /tmp/admin-pw
```

The admin account will have the Matrix ID `@alice:<server.name>`.

`--bootstrap-admin` is a one-shot operation: it creates the user and exits.
Running it again with the same localpart is rejected if the account already
exists.

## 6. Register a normal user (when registration is open)

To allow self-registration, set in the config:

```ini
security.registration.enabled=true
security.registration.require_token=true
security.registration.token_file=/etc/merovingian/registration-token
```

Create the token file:

```sh
openssl rand -base64 48 | sudo tee /etc/merovingian/registration-token
sudo chmod 600 /etc/merovingian/registration-token
```

Register via the API:

```sh
TOKEN=$(sudo cat /etc/merovingian/registration-token)

curl -s -X POST http://127.0.0.1:8008/_matrix/client/v3/register \
  -H 'Content-Type: application/json' \
  -d "{\"username\":\"alice\",\"password\":\"CorrectHorse7!\",
       \"auth\":{\"type\":\"m.login.registration_token\",\"token\":\"$TOKEN\"}}"
# → {"user_id":"@alice:example.org"}
```

To disable the token requirement (not recommended for public servers):

```ini
security.registration.require_token=false
```

## 7. Log in and get an access token

```sh
curl -s -X POST http://127.0.0.1:8008/_matrix/client/v3/login \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "m.login.password",
    "identifier": {"type": "m.id.user", "user": "@alice:example.org"},
    "password": "CorrectHorse7!",
    "device_id": "MY_DEVICE"
  }'
# → {"access_token":"mvs_...","device_id":"MY_DEVICE","user_id":"@alice:example.org"}
```

Save the `access_token` — it is required for all authenticated API calls.

## 8. Connect a Matrix client

Point any Matrix client (Element, Cinny, FluffyChat, etc.) at your
homeserver URL. For web clients the discovery file must be reachable:

```sh
# Verify discovery is working
curl -s https://matrix.example.org/.well-known/matrix/client
# → {"m.homeserver":{"base_url":"https://matrix.example.org"}}
```

If the file returns 404 and your reverse proxy does not forward
`/.well-known/` to Merovingian, create it as a static file:

```sh
sudo mkdir -p /var/www/html/.well-known/matrix
sudo tee /var/www/html/.well-known/matrix/client <<'EOF'
{"m.homeserver":{"base_url":"https://matrix.example.org"}}
EOF
```

If you also publish `/.well-known/matrix/server`, ensure it points to a public
listener that routes federation and key requests to the federation loopback
listener rather than the client listener.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `duplicate configuration key` at startup | Two active `database.backend` lines in the config — remove one |
| `registration token required` on register | Pass `auth.token` in the request body or set `require_token=false` |
| `unknown user` on login (HTTP 403) | User does not exist — register first |
| `bad credentials` on login (HTTP 403) | Wrong password |
| Client shows "Failed to get registration options" | `/.well-known/matrix/client` returns 404 — see step 8 |
| Client OPTIONS requests return 401 | Old build — upgrade to 0.2.10+ |
| Client shows "Connection lost" immediately after login | Old build returning 404 on `/capabilities` or `/pushrules/` — upgrade to 0.2.11+ |
| Client retries `/user/.../filter` every few seconds and never syncs | Old build returning 404 on the filter API — upgrade to 0.2.12+ |
