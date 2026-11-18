# Security review checklist

Use this checklist for every release candidate.

## Authentication

- Password storage uses LibSodium Argon2id and never stores plaintext.
- Access tokens are CSPRNG-generated, high entropy, bearer-only, and stored as
  cryptographic hashes.
- Token comparisons avoid early-exit secret comparison.
- Public registration requires `security.registration.require_token=true` and
  an owner-only `security.registration.token_file`.
- Admin bootstrap is explicit and cannot be claimed by enabling public
  registration.

## Operator surface

- Every `/_merovingian/admin/*` route is a row in `observability::admin_routes()`; the dispatcher answers 404 to
  anything the table does not declare, and `normalized_target` files requests under the row's template (ADR-0504).
  No route stops the process (ADR-0505).
- Authentication (401 missing or invalid, 403 not an administrator) comes before any lookup of the target, so a
  non-administrator cannot learn whether an account exists.
- The account route refuses non-local IDs (400), the caller's own account and other administrators (403), and
  deactivation without `"confirm": true` (400). Its summary carries no hash or token. It reads at most
  4096 bytes of body.

## OAuth 2.0 API

The rules are in `src/homeserver/AGENTS.md` ("OAuth 2.0 API") and `src/oauth/AGENTS.md` ("Rules"); the threats they
answer are in [the threat model](threat-model.md#oauth-20-api-110-adr-0766-to-adr-0817). On a change to this surface:

- **A new page.** It is built only by `oauth::Page` from `HtmlText` or compile-time text (no concatenated markup, no
  `<script>`, event handler, `style=` attribute or remote resource; `src/oauth/AGENTS.md` rule 5, ADR-0815, ADR-0772);
  no member of a page-text type has a default initialiser other than `{}` (rule 12, ADR-0800). The response carries
  `oauth::page_headers()` and sets `LocalHttpResponse::page` (rule 6, ADR-0785), and its route is in
  `request_serves_page` so an escaped exception gets the error page (ADR-0810).
- **A new form action.** The post is refused by `form_post_origin_is_accepted` before its body is read (ADR-0784);
  `Origin`, `Sec-Fetch-Site` and `Cookie` are read with `request_header_values`, a repeated header counting as absent
  (ADR-0788); an account-page action checks the live session, `account_sign_in_gate` and the form token before it acts,
  and calls the client API's own function, never a copy (ADR-0796, ADR-0798). Anything read before
  `verify_password_login` or `create_local_account` is found again after it, since both release `runtime.mutex`. Only a
  post answered by a redirect to a matched client URI passes that `ParsedUri` to `page_headers(target)`.
- **A redirect.** Nothing is redirected before the client and its redirect URI are validated; every address a client
  supplies is read by `ParsedUri::read` and matched with `match_redirect_uri` (rules 3 and 4, ADR-0770). A hand-off
  address is read again with `hand_off_redirect_target` at every step and is always confirmed (ADR-0802).
- **A new OAuth endpoint.** Every answer is built by `oauth_json_response` or `oauth_error_response` with `no-store`
  (ADR-0781); every absolute address comes from `OAuthBaseUrl` with an `OAuthPaths.hpp` constant (rule 9, ADR-0773);
  the route has a rate-limit tier (`auth_sensitive` unless the spec says otherwise, ADR-0775), its `static_routes` and
  `client_static_route_allow` rows, and a row in `test_route_query_conformance.cpp`; `client_secret` and
  `Authorization: Basic` are refused (`oauth_client_credentials_refusal`); a client is read back with
  `find_registered_oauth_client`.
- **A new store.** It is in memory, keeps every secret only as `oauth_secret_hash`, compares in constant time, has a
  total cap and a per-address (or per-user) cap, never evicts a live entry, takes the clock from `oauth_wall_clock_ms`
  (or `oauth_device_clock_ms` for the device grant), and is guarded by `runtime.mutex` (ADR-0782, ADR-0805). A store
  that can name a client is counted by `oauth_client_has_pending_authorisation`, or the client cap and the sweep may
  delete a client in use (ADR-0780, ADR-0782).
- **A new path that issues a session.** It writes through `grant_oauth_session` / `database::store_oauth_grant` in one
  transaction, with nothing that can fail after the commit (ADR-0792); it judges the account again with
  `account_sign_in_gate` and compares the credential stamp of its password check with `user_credential_stamp_matches`
  (ADR-0807); a route that issues a legacy session asks `legacy_auth_refusal` first (ADR-0801).
- **A new path that ends a session.** It goes through `end_device_session_and_announce` and announces the deleted
  devices (ADR-0795); a revocation of a device's last credential deletes its `oauth_sessions` row in the same transaction
  (ADR-0808). A new UIA endpoint calls `oauth_session_uia_refusal` first (ADR-0794).
- **A new path that changes a password or closes an account.** It calls `end_account_page_access` (ADR-0798), and the
  new password hash changes the credential stamp, so a sign-in in progress fails its stamp check (ADR-0807).
- **Logging.** No code, verifier, token, password, cookie, form token, device or user code, credential stamp, body or
  query is logged; `sanitized_http_target` drops the query of every OAuth and account path (ADR-0786); a refusal logs
  `client_id` only once `find_registered_oauth_client` found it.
- **Tests.** The change has a scenario that drives `handle_client_server_request` (in `tests/integration/`), and a page
  change keeps `test_oauth_page.cpp`'s policy-hash check passing. Note in the review what still needs a real browser
  (cookies, `SameSite`, `form-action` on a redirect).

## Federation

- Request signatures are verified with Matrix canonical JSON.
- Event signatures are verified with Ed25519 for the expected origin.
- Key fetch, DNS, well-known, TLS, and private-address controls are covered by
  integration tests.
- Replay windows, backoff, quarantine, and audit logging are tested.

## Federation worker IPC

- The main process and `merovingian-fed-worker` complete a mutually authenticated
  `crypto_kx` handshake keyed from a hash of the operator master key
  (`crypto::derive_ipc_auth_key`) before any frame is trusted; a peer that cannot
  prove possession of the master key is rejected, fail-closed.
- Frames are `crypto_secretstream` AEAD-encrypted after the handshake
  (`crypto::IpcStreamCipher`); a process that can read the socket pair without
  completing the handshake sees only ciphertext.
- The Ed25519 signing key and inbound client credentials (`Authorization`/
  `X-Matrix` headers, access tokens) never cross the channel, and the worker
  cannot ask main to sign: there is no `sign_request` frame, main answers one
  with an error and no signature without taking the runtime lock, and the
  worker's provider (`crypto::RefusingEd25519Provider`) refuses every sign and
  verify request (ADR-0078).
- The worker refuses to start unsandboxed: on a platform with no seccomp
  equivalent, hardening failure is fail-closed (federation degrades to 503)
  rather than running unconfined while logging hardening as active.
- The worker is spawned with a minimal environment (`PATH` only), so no secret
  in main's environment leaks to the worker via inheritance.

## Application Service API

- `as_token`/`hs_token` are held in `SecretBuffer`, never logged, and compared
  with `crypto::constant_time_equal`.
- Namespace regexes are matched with `std::regex_match` against the whole
  identifier, never `std::regex_search`, so a namespace claim cannot swallow an
  unrelated identifier as a substring match.
- Registration `id` and `as_token` uniqueness and exclusive-namespace conflicts
  are enforced at boot (`validate_registrations()`); a conflicting set fails
  the whole set closed rather than resolving by load order.
- Outbound transaction delivery (`AppserviceClient.cpp`) is a deliberate,
  narrow exception to the outbound SSRF policy: it resolves the appservice
  `url` directly and allows plain `http://`, because that URL comes from an
  operator-placed registration file, not network-reachable input — see
  `docs/threat-model.md`, "Outbound Application Service API transaction
  delivery".

## Identity Service client

- Every Identity Service host resolves to SSRF-safe pinned addresses via
  `federation::CachedServerDiscovery`'s `deny_ip_ranges` before any request is
  made; the client never performs its own DNS lookup and never accepts a
  client-supplied address, failing closed when resolution yields nothing usable.
- Identity Service base URLs must be `https://`; certificate and hostname
  verification apply and redirects are refused.
- The homeserver's signing key and `Authorization: X-Matrix` are never sent to
  an Identity Service; authenticated calls use a bearer `id_access_token`
  instead, and the call site confirms the target is in
  `server.identity_server.trusted_servers` first.

## Push gateway delivery

- A pusher's gateway URL is attacker-influenced (any client can register one
  pointing anywhere) and is independently re-validated as `https://` with a
  path of exactly `/_matrix/push/v1/notify` before resolution is attempted.
- The gateway host resolves through `federation::CachedServerDiscovery`'s
  pinned-address/`deny_ip_ranges` path, the same as federation and identity
  outbound calls.
- Registration is bounded: `POST /pushers/set` refuses a new pusher past
  `server.push.max_pushers_per_user` (default 20); updating an existing one is allowed.
- Delivery is bounded too: at most
  `server.push.max_pushers_per_delivery` (default 25) pushers are contacted per
  recipient of an event (the cap applies to each recipient's pusher list, so one
  event can contact more across its recipients), and at most `server.push.max_in_flight_deliveries` (default 256)
  deliveries run concurrently process-wide. Both are configuration values
  (`config/PushConfig.hpp`), validated at load in `src/config/Config.cpp`.
- `notify()` and the delivery scheduler both re-check `server.push.enabled`
  before any DNS lookup, connection, or byte leaves the process.

## Cross-signing over federation

- A stored key signature is merged into a published key only through
  `federation::merge_visible_key_signatures()`, `published_device_keys()`, or
  `published_cross_signing_key()` (`KeySignatures.hpp`) — never by hand
  elsewhere.
- An uploaded signature is shown only to its uploader's own audience unless the
  uploader owns the key, so an upload cannot speak for another user
  (ADR-0060).
- Remote users' cross-signing keys are proxied from their own server at query
  time and never cached locally; `cross_signing_keys` holds local users only
  (ADR-0061).

## Persistence

- Runtime data is durable in SQLite or PostgreSQL.
- All write paths use prepared statements and transactions.
- Schema upgrades, downgrades, and incompatible schemas fail safely.
- Secrets and event contents are redacted from logs, metrics, and SQL summaries.

## Runtime hardening

- Linux packages use a locked-down systemd unit.
- BSD packages use an unprivileged service user and isolated data/log paths.
- Core dumps are disabled for secret-bearing processes.
- Production health fails if required hardening is disabled or unknown.

## Media

- Upload size, MIME validation, content hashing, quarantine, and admin actions
  are integration-tested.
- Remote media fetches resolve the origin server via federation discovery,
  reject resolved addresses that are private or loopback
  (`media::remote_media_fetch_policy`), and re-resolve and re-pin any
  `Location` redirect before following it (`resolve_media_redirect_url()`);
  fetched bytes are never marked scanner-clean and are quarantined by default
  (`security.media.remote_fetch_media_policy`).
- Any decoder runs in a sandboxed worker with no network.

## Release evidence

- A `v<version>` tag naming the `meson.build` version publishes hardened Linux
  and FreeBSD tarballs, carrying both workers, plus SHA-256 checksum files
  through `.github/workflows/release.yml`; any other tag is refused (ADR-0597).
- CI (`ci.yml`, covering Linux and BSD build/test jobs), sanitizers
  (`sanitizers.yml`), static-analysis (`static-analysis.yml`), fuzz
  (`fuzz.yml`), and reproducible-build (`reproducible-build.yml`) workflows
  passed, and `scripts/check-release-readiness.sh` (run from `ci.yml` and
  `release.yml`) passed.
- CodeQL (`codeql.yml`), secret-scanning (`secret-scan.yml`),
  and dependency-triage (`dependency-vulnerability-triage.yml`) workflows
  passed for the release candidate commit.
  CodeQL's report reaches code scanning through `scripts/filter_codeql_sarif.py`,
  which drops only `cpp/unused-static-function` on files under `tests/`
  (Catch2 scenarios, ADR-0226), every result on the vendored `subprojects/`
  and the `build/` directory (ADR-0527), and `cpp/path-injection` whose every
  source is a command-line argument (ADR-0528); any other exclusion added there
  needs its own ADR and is reviewed like a dismissed alert.
- The SonarQube Cloud quality gate passed for the release candidate commit.
  It analyses the server (`src/`, `include/`), `packaging/` and the
  `.github/` workflows; test code and developer tooling (`tests/`,
  `scripts/`, `build.py`, `llvm.sh`, `.codex/`) are excluded in
  `sonar-project.properties` (ADR-0229). The analysis runs in CI
  (the scan step of `.github/workflows/coverage.yml`) against the build's compilation
  database, with coverage from every suite (ADR-0250); a `coverage` job whose scan
  step did not run for the commit is
  not a pass. A finding in an analysed path is
  fixed or reviewed in SonarQube, never hidden by widening that list.
- Dependency vulnerability triage artifacts were reviewed before tagging.
- The SBOM (`merovingian.spdx.json`, `merovingian.cdx.json`) and package
  checksums are attached, each with its `.asc` signature (ADR-0598).
- Release artifacts are signed with a detached GPG `.asc` signature by the
  maintainer key (`.github/workflows/sign-artifacts.yml`; verify with
  `gpg --verify <file>.asc <file>`).
