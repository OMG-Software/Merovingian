# src/config/ — Configuration Module

Parses and validates the server configuration and plans (but does not yet apply) reloads.

## Key files

| File | Responsibility |
|---|---|
| `Config.cpp` | `Config` class (its section structs, such as `ServerConfig`, `ListenersConfig`, `DatabaseConfig` and `SecurityConfig`, each have their own `<TypeName>.hpp`) — typed representation of every config option; `validate_config()`, `parse_size_limit()` |
| `config_parser.cpp` | Parses the key-value `.conf` file into `Config`; validates ranges and required fields |
| `runtime_config.cpp` | `RuntimeConfigSnapshot`: holds a `Config` and can swap it for a reload-only candidate. Only the unit tests construct it today; the server does not |
| `reload_plan.cpp` | Diffs old vs new config and classifies each change; used by `--plan-config-reload`. No live reload path (SIGHUP/admin socket) exists yet |
| `reload_policy.cpp` | `reload_policy_for_key()`: which keys need a restart. Keys are reloadable by default. Restart is required for `server.name`, the `database.*` URI and role keys, listener TLS certificate/key and `reverse_proxy` keys, `security.registration.token_file`, `database.pool_size`, `security.media.thumbnail_cache_size`, `security.media.thumbnail_max_concurrent_per_user`, `security.secrets.master_key_file`, `security.federation.key_resolution_*`, `security.federation.join_response_max_size`, `client_rate_limits.*`, `log_modules.*`, `federation.worker.*`, `server.cors.*`, `server.http.*`, `server.identity_server.*`, `server.push.*`, `appservice.*` and `presence.*`. The rate-limit engine and per-module log map are built once at start-up, so they are not hot-reloadable. |

## Rules

- **Never read config values directly from environment or disk inside other modules.**
  All config access goes through `runtime_config.hpp` — it provides a snapshot that is safe to
  read under concurrent requests.
- **Validate at parse time, not at use time.** If a value is out of range or missing, reject it
  in `config_parser.cpp` and return an error — do not let bad config reach the runtime.
- **Log the effective config at startup** (INFO level) excluding secrets. Never log TLS private
  key paths or secret values.
- **Reload planning** is handled by `reload_plan.cpp`; nothing applies a reload at runtime yet, so
  every change needs a restart today. Keep the classification documented in `docs/user-manual.md`
  (Reloadability policy) in step with `reload_policy.cpp`.

## Size limit parsing

`config::parse_size_limit()` converts strings like `"100MiB"`, `"1GiB"` into byte counts. It
accepts a positive integer with the suffix `B`, `KiB`, `MiB` or `GiB` (or none); `100M` and
`1G` are rejected. An optional size limit is empty for "no limit"; `validate()` must reject
any other value that fails to parse, because a size that parses as invalid reads as 0, which
callers treat as no limit (OPS-3).
Use this helper everywhere a config value represents a byte limit — do not parse inline.

## Key doc

- `docs/user-manual.md` — all config keys, types, defaults, and restart requirements
