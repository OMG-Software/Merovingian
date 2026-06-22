# src/config/ — Configuration Module

Parses, validates, and hot-reloads the server configuration.

## Key files

| File | Responsibility |
|---|---|
| `config.cpp` | `ServerConfig` struct — typed representation of every config option |
| `config_parser.cpp` | Parses the key-value `.conf` file into `ServerConfig`; validates ranges and required fields |
| `runtime_config.cpp` | Holds the live `ServerConfig` and exposes it thread-safely for other modules |
| `reload_plan.cpp` | Diffs old vs new config to determine which changes can be applied live |
| `reload_policy.cpp` | Rules for what is hot-reloadable (log level, rate limits) vs requires restart (TLS cert, port) |

## Rules

- **Never read config values directly from environment or disk inside other modules.**
  All config access goes through `runtime_config.hpp` — it provides a snapshot that is safe to
  read under concurrent requests.
- **Validate at parse time, not at use time.** If a value is out of range or missing, reject it
  in `config_parser.cpp` and return an error — do not let bad config reach the runtime.
- **Log the effective config at startup** (INFO level) excluding secrets. Never log TLS private
  key paths or secret values.
- **Hot-reload** is handled by `reload_plan.cpp`; changes that require restart must be documented
  in `docs/configuration.md` with the `requires_restart` flag.

## Size limit parsing

`config::parse_size_limit()` converts strings like `"100M"`, `"1G"` into byte counts.
Use this helper everywhere a config value represents a byte limit — do not parse inline.

## Key doc

- `docs/configuration.md` — all config keys, types, defaults, and restart requirements
