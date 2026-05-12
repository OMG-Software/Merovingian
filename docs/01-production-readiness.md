# Production readiness

The Merovingian is not production-ready until every release gate below passes in
CI and the release artifact records the evidence. Packaging files exist so Linux
and BSD operators can test deployment shape early, but packages must not be
published as production releases while any blocking gate is open.

Progress is tracked by capability in `docs/progress.md`. Matrix v1.18 endpoint
coverage is tracked in `docs/protocol-coverage.md`. Numbered milestone and phase
documents are historical notes only.

## Blocking gates

- The server executable must keep real listener coverage in CI and serve
  requests until it is stopped by the service manager.
- Client-server routes run through the socket accept/read/write loop and the
  Matrix JSON adapter. They still require full Matrix v1.18 conformance,
  persistence, endpoint coverage, and production-grade rate limiting before
  release.
- Access tokens must be generated with LibSodium CSPRNG output and stored only as
  versioned cryptographic hashes.
- Passwords must be stored with LibSodium Argon2id password hashes.
- Federation request and event verification must use Matrix canonical JSON and
  real Ed25519 verification.
- SQLite or PostgreSQL persistence must be used for runtime data, with migration
  tests against real temporary databases.
- Runtime hardening checks must fail closed when required production controls are
  unavailable.
- Conformance, fuzz, sanitizer, static-analysis, and packaging checks must pass
  before a release tag is created.
- CodeQL, coverage, sanitizer, static-analysis, and Linux CI jobs install
  LibSodium development headers before configuring Meson so production
  cryptographic dependencies are validated consistently.

## Packaging targets

- `packaging/systemd/merovingian.service` provides a hardened Linux service unit.
- `packaging/openrc/merovingian` provides an OpenRC service script.
- `packaging/rc.d/merovingian` provides a BSD rc.d service script.
- `Dockerfile` builds a minimal Debian runtime image.

## Release command sequence

```sh
sh scripts/setup-dev-env.sh --check-only
meson setup build -Dbuild_tests=true -Dbuild_fuzz=true
meson compile -C build
meson test -C build --print-errorlogs
sh scripts/reject-unsafe.sh
sh scripts/check-release-readiness.sh
```

The release operator records compiler version, linker flags, dependency
versions, test logs, sanitizer logs, fuzz target names, package checksums, and
artifact signatures in the release notes.
