# Production readiness

The Merovingian is not production-ready until every release gate below passes in
CI and the release artifact records the evidence. Packaging files exist so Linux
and BSD operators can test deployment shape early, but packages must not be
published as production releases while any blocking gate is open.

## Blocking gates

- The server executable must run a real listener and serve requests until it is
  stopped by the service manager.
- Client-server routes must run through the socket accept/read/write loop. The
  current client-server facade accepts Matrix JSON request bodies for
  registration, password login, and device updates, and has a single-request
  HTTP/1.1 adapter for tests. The public client-server API is production-named
  through `client_server.hpp`, but runtime listeners do not yet read requests
  from sockets.
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
