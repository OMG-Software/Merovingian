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
  `X-Matrix` headers, access tokens) never cross the channel — the worker asks
  main to sign via `sign_request`/`sign_response` frames and
  `IpcEd25519Provider::verify()` terminates the process if ever called.
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
- Outbound transaction delivery (`appservice_client.cpp`) is a deliberate,
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
- Delivery, not registration, is bounded: at most `k_max_pushers_per_delivery`
  (10) pushers are contacted per event, and at most
  `k_max_in_flight_push_deliveries` (128) deliveries run concurrently
  process-wide; both caps live in `room_service.cpp`.
- `notify()` and the delivery scheduler both re-check `server.push.enabled`
  before any DNS lookup, connection, or byte leaves the process.

## Cross-signing over federation

- A stored key signature is merged into a published key only through
  `federation::merge_visible_key_signatures()`, `published_device_keys()`, or
  `published_cross_signing_key()` (`key_signatures.hpp`) — never by hand
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

- Alpha tags matching `v*-alpha*` publish hardened Linux and FreeBSD tarballs
  plus SHA-256 checksum files through `.github/workflows/release.yml`.
- CI (`ci.yml`, covering Linux and BSD build/test jobs), sanitizers
  (`sanitizers.yml`), static-analysis (`static-analysis.yml`), fuzz
  (`fuzz.yml`), and reproducible-build (`reproducible-build.yml`) workflows
  passed, and `scripts/check-release-readiness.sh` (run from `ci.yml` and
  `release.yml`) passed.
- CodeQL (`codeql.yml`), secret-scanning (`secret-scan.yml`),
  dependency-triage (`dependency-vulnerability-triage.yml`), and SBOM
  (`sbom.yml`) workflows passed for the release candidate commit.
- Dependency vulnerability triage artifacts were reviewed before tagging.
- SBOM and package checksums are attached.
- Release artifacts are signed with a detached GPG `.asc` signature by the
  maintainer key (`.github/workflows/sign-artifacts.yml`; verify with
  `gpg --verify <file>.asc <file>`).
