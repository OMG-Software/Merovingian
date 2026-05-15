# Dependency reviews

This folder records reviewed third-party dependencies and the boundary each one
is allowed to cross. Each dependency must remain behind a project-owned module
or tooling boundary so upstream APIs do not leak across the homeserver.

## Reviewed dependencies

| Dependency | Scope | Review |
| --- | --- | --- |
| LibSodium | Runtime cryptography | [libsodium.md](libsodium.md) |
| OpenSSL | Runtime TLS listener boundary | [openssl.md](openssl.md) |
| PostgreSQL libpq | Runtime PostgreSQL client | [postgresql-libpq.md](postgresql-libpq.md) |
| SQLite | Runtime/development embedded database | [sqlite.md](sqlite.md) |
| yyjson | Canonical JSON parser adapter | [yyjson.md](yyjson.md) |
| Catch2 | Test framework | [catch2.md](catch2.md) |

## Review rules

- Runtime dependencies must be wrapped behind a Merovingian namespace boundary.
- Third-party handles must be RAII-managed before they leave the implementation
  file that owns them.
- Third-party headers should be treated as system includes where supported so
  warning-as-error applies to project code.
- Wrap fallbacks are for bootstrap and CI reproducibility; system packages
  remain preferred for production builds.
- Test-only dependencies must not be linked into production targets.
