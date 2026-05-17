# Phase 1: Secure bootstrap configuration

Historical note: this document records the original secure-configuration phase.
It is not the current project progress source. Current progress is tracked in
`docs/01-progress-tracker.md`.

Phase 1 establishes a secure, validated bootstrap path before adding Matrix runtime behavior.

## Completed in Phase 1

- Typed configuration model for server, listeners, database, registration, encryption, federation, media, and logging settings.
- Secure compiled defaults.
- Fail-closed configuration validation.
- Dependency-free `key=value` parser for the Phase 1 bootstrap format.
- Bounded config file loading before parsing.
- Parser rejection for unknown keys, duplicate keys, malformed lines, invalid typed values, oversized files, and oversized lines.
- Optional `--config <path>` startup support.
- `--help`, `-h`, and `--version` bootstrap flags.
- Explicit bootstrap exit codes.
- Safe startup summary logging for non-secret metadata after validation passes.
- Checked-in secure starter config at `config/merovingian.conf.example`.
- Configuration documentation and README run guidance.
- Unit tests for config defaults, validation, parser behavior, and parser bounds.
- Smoke tests for default startup, example config startup, valid config-file startup, invalid config rejection, oversized config rejection, help, version, invalid arguments, exit codes, and safe startup summaries.
- Explicit CI gate for Phase 1 config behavior.
- Config/parser implementation split out of public headers into `src/config`.

## Security posture

Phase 1 is intentionally narrow. It does not start a Matrix API listener, accept client traffic, process federation traffic, parse events, connect to a database, handle media, or perform cryptographic operations.

The bootstrap path now provides these guarantees:

- Startup uses secure compiled defaults when no config file is supplied.
- Startup validates file-backed configuration before continuing.
- Parser and validation findings stop startup before runtime work begins.
- Public cleartext listeners are rejected.
- Open registration without token protection is rejected.
- Weakened encryption, federation, media, and logging protections are rejected.
- Config input is bounded and duplicate keys are rejected.
- Startup logs do not include secrets, database URI contents, access tokens, or Matrix event contents.

## Intentionally deferred

These are not part of Phase 1:

- Matrix Client-Server API implementation.
- Matrix Federation API implementation.
- Database connectivity and schema management.
- TLS implementation and certificate loading.
- Runtime listener/socket setup.
- YAML/TOML/JSON config dependencies.
- Registration token generation or storage.
- Media repository implementation.
- Event auth, signing, canonical JSON, or federation signature verification.
- End-to-end encryption protocol handling.
- Runtime sandboxing implementation.
- Full hardening self-check reporting.
- POSIX file permission enforcement for config and secret files.

## Phase 2 entry criteria

Phase 2 should start only after Phase 1 is merged and CI is green.

Recommended Phase 2 starting points:

1. Add a small platform abstraction for POSIX file metadata and permission checks.
2. Add config/secret file permission validation.
3. Add runtime listener scaffolding without Matrix endpoints.
4. Add database connection configuration without storing credentials in logs.

## Review checklist

Before merging Phase 1, verify:

- CI passes.
- `config/merovingian.conf.example` validates.
- Invalid configs fail closed.
- No secrets are logged in startup summaries.
- Public headers contain declarations and types, not the main config/parser implementation.
- No new unsafe allocation patterns are introduced.
