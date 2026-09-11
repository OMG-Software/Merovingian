# src/config/ — Configuration Module

Parses, validates, and hot-reloads the server configuration.

## Key files

| File | Responsibility |
|---|---|
| `config.cpp` | `Config` class and its section structs (`ServerConfig`, `ListenersConfig`, `DatabaseConfig`, `SecurityConfig`, …) — typed representation of every config option; `validate_config()`, `parse_size_limit()` |
| `config_parser.cpp` | Parses the key-value `.conf` file into `Config`; validates ranges and required fields |
| `runtime_config.cpp` | Holds the live `Config` and exposes it thread-safely for other modules |
| `reload_plan.cpp` | Diffs old vs new config to determine which changes can be applied live |
| `reload_policy.cpp` | `reload_policy_for_key()`: which keys need a restart. Keys are reloadable by default. Restart is required for `server.name`, the `database.*` URI and role keys, listener TLS certificate/key and `reverse_proxy` keys, `security.registration.token_file`, `security.secrets.master_key_file`, `security.federation.key_resolution_*`, `security.federation.join_response_max_size`, `client_rate_limits.*`, `log_modules.*`, `federation.worker.*`, `server.cors.*`, `server.http.*`, `server.identity_server.*`, `server.push.*` and `appservice.*`. The rate-limit engine and per-module log map are built once at start-up, so they are not hot-reloadable. |

## Rules

- **Never read config values directly from environment or disk inside other modules.**
  All config access goes through `runtime_config.hpp` — it provides a snapshot that is safe to
  read under concurrent requests.
- **Validate at parse time, not at use time.** If a value is out of range or missing, reject it
  in `config_parser.cpp` and return an error — do not let bad config reach the runtime.
- **Log the effective config at startup** (INFO level) excluding secrets. Never log TLS private
  key paths or secret values.
- **Hot-reload** is handled by `reload_plan.cpp`; changes that require restart must be documented
  in `docs/user-manual.md` (Reloadability policy) with the `requires_restart` flag.

## Size limit parsing

`config::parse_size_limit()` converts strings like `"100M"`, `"1G"` into byte counts.
Use this helper everywhere a config value represents a byte limit — do not parse inline.

## Key doc

- `docs/user-manual.md` — all config keys, types, defaults, and restart requirements
