# Security review checklist

Use this checklist for every release candidate.

## Authentication

- Password storage uses LibSodium Argon2id and never stores plaintext.
- Access tokens are CSPRNG-generated, high entropy, bearer-only, and stored as
  cryptographic hashes.
- Token comparisons avoid early-exit secret comparison.
- Admin bootstrap is explicit and cannot be claimed by enabling public
  registration.

## Federation

- Request signatures are verified with Matrix canonical JSON.
- Event signatures are verified with Ed25519 for the expected origin.
- Key fetch, DNS, well-known, TLS, and private-address controls are covered by
  integration tests.
- Replay windows, backoff, quarantine, and audit logging are tested.

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
- Remote media fetches remain disabled until SSRF, DNS rebinding, and cache
  controls are implemented.
- Any decoder runs in a sandboxed worker with no network.

## Release evidence

- CI passed normal, sanitizer, static-analysis, BSD, fuzz, and release-readiness
  workflows.
- Dependency and license reports are attached.
- SBOM and package checksums are attached.
- Release artifacts are signed.
