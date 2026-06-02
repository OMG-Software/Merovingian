# Log filtering and failure routing (0.5.0 design)

## Problem statement

When the operator passes `--debug`, the diagnostic firehose drowns the
single signal line they were looking for. The current architecture is
flat:

- Every `log_diagnostic(event, fields)` call in the codebase — 40+ call
  sites across `auth/identity`, `auth/session`, `auth/token`,
  `crypto/signing_service`, `database/migration`,
  `database/persistent_store`, `database/postgresql_store`, and every
  module under `homeserver/` — emits at `LOG_DEBUG`.
- `SingleLog` in `include/merovingian/observability/logger.hpp` exposes
  only two knobs: a console level and a file level. Console defaults to
  `info` and goes to `debug` if `--debug` is passed; the file level is
  hard-wired to `trace` and cannot be raised above trace from the
  operator side.
- The logger takes only `(level, line)`. There is no logger-name
  filtering, no event-name filtering, no category, and no
  actor/severity-based filtering at the logger boundary. The only
  categorisation is the prefix string in `diagnostic_log_summary`
  (e.g. `debug session event=registration_policy.denied reason=registration
  disabled`).
- A typical `--debug` session produces 50–200 lines per request
  (`request.received`, `request.dispatch`, `access_token.accepted`,
  `request.auth.accepted`, `sync.dispatch`,
  `sync_notifier event=stream.changed`, `request.completed`,
  `room.typing.accepted`, `sync_notifier event=stream.published`, …).
  The `status=400` "registration disabled" line is buried.
- Failures (`login.rejected`, `registration_policy.denied`,
  `access_token.rejected`, `request.rejected`, `room.rejected`) are
  logged with the same DEBUG level and the same file sink as the
  success path, so there is no on-disk signal you can grep for that
  says "this request failed".
- The same code path often writes TWO events — e.g.
  `log_diagnostic("login.rejected", …)` followed by
  `client_server event=request.rejected status=429 reason=rate limit
  exceeded` — so even a high-signal search like "rejected" matches
  dozens of background events per request.

The `audit_log` table already records durable, structured
`category/event_type/actor/target/reason` rows for security-significant
actions (`auth.user_registered`, `auth.login`, `device.deleted`,
`room.created`, `media.upload_rejected`, `runtime.started`, …) and the
`/_merovingian/admin/audit` endpoint exposes them. **But** failure
paths like `login.rejected`, `registration_policy.denied`,
`access_token.rejected`, `request.rejected`, and the rate-limit 429 do
NOT write to `audit_log` — they only fire the same noisy
`log_diagnostic`. So even the admin audit endpoint doesn't help for
those.

## Goals

After this change, the operator must be able to:

1. Run the server with `--debug` and see only the events they care
   about (the high-signal loggers — `auth`, `local_services`,
   `event_auth`, `signing_service`, `rooms`, `event_auth`,
   `persistent_store`) at DEBUG, with the noisy operational noise
   (`http_server`, `sync_notifier`, `local_router`) silenced by
   default.
2. Find every failure across a session with a single command:
   `GET /_merovingian/admin/audit?category=policy&since=<ts>` — a
   structured, queryable view rather than a 10 MB text file to grep.
3. Override the noise floor per-logger via a config section
   (`log_modules: { http_server: info, sync_notifier: warning, ... }`)
   without recompiling.
4. Have the `/register` and `/login` rate limits not block legitimate
   single-user registration flows on a quiet server (today's cap of
   "5 / 64 requests" is not a wall-clock limit at all; it freezes
   until the server-wide request clock reaches 64).

## Non-goals

- No Prometheus/OpenMetrics scrape contract.
- No distributed tracing or correlation IDs.
- No operator dashboards.
- No `failures.log` companion file sink — logs go to stdout, so a
  dedicated file sink adds operational burden without a matching
  benefit. Stdout remains the only file destination.
- No change to any successful-flow log line; `*.accepted` /
  `*.persisted` / `*.started` stay at debug/info.
- No schema migration; the existing `audit_log` columns
  (`category`, `event_type`, `actor`, `target`, `reason`) already
  cover the need.

## Design

### 1. Per-event severities

A new `enum class LogEventSeverity { trace, debug, info, notice,
warning, error, critical }` in
`include/merovingian/observability/logger.hpp`. The
`log_diagnostic(event, fields, severity = LogEventSeverity::debug)`
helper takes a severity and forwards to the correct
`SingleLog::level`. Default `LogEventSeverity::debug` keeps every
existing call site working without mechanical edits.

A second helper `log_diagnostic_audit(event, fields, severity)` is
the audit-wired sibling: when `severity >= warning`, it additionally
writes a `category=policy` row to `audit_log` with
`event_type=<logger>.<event>` and `reason=<message>` (see #3). This
is the only helper that needs a deliberate call-site decision; plain
`log_diagnostic` continues to be a pure diagnostic.

### 2. Per-logger-name level filtering

`SingleLog` gains:

- `set_module_log_level(std::string_view logger, LogLevel level)` —
  sets the per-logger level.
- `set_default_log_level(LogLevel)` — wildcard default; defaults to
  `info`.
- The module name is the first whitespace-delimited token in the
  diagnostic line (e.g. `http_server`, `auth`, `sync_notifier`).

A new `log_modules` config section in `merovingian.conf` with
overrides per module, hot-reloaded on SIGHUP. The new `--debug`
default floor is:

| Module | Default level | Why |
|---|---|---|
| `http_server` | `info` | Every request lifecycle is here — pure noise on debug. |
| `client_server` | `info` | Same: one event per request dispatch. |
| `sync_notifier` | `warning` | `stream.timeout` and `stream.changed` fire every few seconds. |
| `local_router` | `info` | Room/media/federation dispatch — operator care. |
| `auth` | `debug` | This is the high-signal logger for logins/tokens. |
| `local_services` | `debug` | Audit appends — operator needs every one. |
| `event_auth` | `debug` | Auth-rule rejections are the key join-failure signal. |
| `signing_service` | `debug` | Sign accepted/rejected/failed. |
| `rooms` | `debug` | Room creation, event composition, persistence. |
| `persistent_store` | `debug` | Event/membership/invite persistence. |
| `event_signer` | `debug` | Federation event signing. |
| `local_router` | `info` | Dispatch decisions are useful only when something fails. |
| `federation` | `debug` | Federation policy/sig/transaction decisions. |
| `db_migrate` | `info` | Plan/step outcomes. |
| `runtime` | `debug` | Startup/shutdown wiring. |

`--debug` preserves the previous "show me everything at debug"
behaviour via the explicit `log_modules: { "*": "debug" }` override
in the config.

### 3. Failure routing into `audit_log`

`append_local_audit_if_failure(category, event_type, actor, target,
reason, severity)` (sibling of the existing `append_local_audit`)
writes a row to `audit_log` only when `severity >= warning`. The
four call sites that today only `log_diagnostic` are upgraded to
use this new helper, with the right category:

| Call site | Event | Severity | audit_log row |
|---|---|---|---|
| `http/rate_limit.cpp` | `rate_limit.exceeded` | `warning` | `category=policy`, `event_type=rate_limit.exceeded`, `reason=<max/60s>` |
| `homeserver/auth_service.cpp` | `login.rejected` | `warning` | `category=auth`, `event_type=login.rejected`, `reason=<m.forbidden|...>` |
| `homeserver/auth_service.cpp` | `access_token.rejected` | `warning` | `category=auth`, `event_type=access_token.rejected`, `reason=<expired|invalid|...>` |
| `homeserver/client_server.cpp` | `request.rejected` (4xx/5xx) | `warning` | `category=policy`, `event_type=request.rejected`, `reason=<status code/errcode>` |
| `auth/session.cpp` | `registration_policy.denied` | `warning` | `category=policy`, `event_type=registration_policy.denied`, `reason=<disabled|token_required|...>` |

`/_merovingian/admin/audit` gains `?category=…&since=…&event_type=…`
filter query parameters so the operator can ask for "all policy
failures in the last hour" without dumping the whole table.

### 4. Rate-limit rewrite: wall-clock, configurable, restart-resetting

Today the rate limiter is a request-counter window
(`rt.limits.rate_limit_window_requests=64`), not a wall-clock
window. The "5 per 60 seconds" advertised in the docs is a lie; the
real effective cap on `/register` and `/login` is **5 per 64
server-wide requests**, with no wall-clock reset. On a quiet server
the bucket is "frozen" at 5 until traffic builds up, which is why
the operator cannot register a single user without first generating
64 unrelated server requests.

The fix has three parts:

- **Wall-clock window.** The bucket roll-over key is changed from
  `request_clock` (counter) to `wall_clock` (time-point). The
  `Clock` typedef already exists on `HomeserverRuntime`; the
  rate-limiter takes it as an injected dependency so the unit tests
  use a `manual_clock` fixture instead of `sleep_for`.
- **Restart wipes the counter.** The bucket table is in-process on
  `ClientServerRuntime::rate_limit_buckets` (a `std::vector`); a
  restart of the server process drops the in-memory state. No
  on-disk persistence is added — per the operator's request.
- **Configurable caps and a new per-user login cap.** New
  `ClientRateLimitsConfig` block in `merovingian.conf` (hot-reloaded
  on SIGHUP). New defaults:

| Route | Old (per-IP) | New (per-IP) | New (per-user, login only) |
|---|---|---|---|
| `POST /_matrix/client/v3/login` | 5 / 64 reqs | **20 / 60s** | **5 / 60s** |
| `POST /_matrix/client/v3/register` | 5 / 64 reqs | **20 / 60s** | n/a (no user yet) |
| `POST /_matrix/client/v3/keys/upload` | 30 / 64 reqs | 30 / 60s | n/a (already authed) |
| `GET/POST /_matrix/client/v3/keys/claim` | 30 / 64 reqs | 30 / 60s | n/a |
| `/_matrix/media/*` | 20 / 64 reqs | 20 / 60s | n/a |
| `/_matrix/federation/*` | 64 / 64 reqs | 120 / 60s | n/a |
| default | 60 / 64 reqs | 60 / 60s | n/a |

The **20 / 60s per-IP** for `/register` is sized for the natural
client traffic: Element Web fires OPTIONS + probe + final = 3
requests per registration, Cinny fires 2–3, and real-world retry on
a flaky network doubles that. 20/min/IP leaves headroom for a
small office's worth of users registering in sequence from the same
corporate NAT without being exploitable. The **5 / 60s per-user
login cap** is the credential-stuffing defence: with a 20/min per-IP
floor and 5/min per-user ceiling, a single attacker has to hit 20
IPs to land 5 attempts against the same user in a minute — the
standard rate of a Tier-1 brute-force attack. Anything tighter is
hostile to password-manager autofill; anything looser invites
automated stuffing.

## Files to add / change

| File | Purpose |
|---|---|
| `docs/log-filtering-design.md` (this file) | Plan, sign-off, rationale. |
| `docs/log-filtering.md` (new) | Operator usage recipes. |
| `docs/debug-logging.md` | Update `--debug` semantics; new module-level filter recipe; "look in `/_merovingian/admin/audit` first" triage recipe. |
| `docs/configuration.md` | New `ClientRateLimitsConfig` and `LogModulesConfig` sections. |
| `docs/observability-audit.md` | New failure-routing section. |
| `docs/01-progress-tracker.md` | 0.5.0 section. |
| `CHANGELOG.md` | 0.5.0 entry. |
| `merovingian.conf.example` | New defaults, commented examples. |
| `packaging/rpm/merovingian.spec` | New 0.5.0 `%changelog` entry. |
| `include/merovingian/observability/logger.hpp` + `src/observability/logger.cpp` | `LogEventSeverity`, `set_module_log_level`, `set_default_log_level`, `log_diagnostic_audit`. |
| `include/merovingian/homeserver/client_server.hpp` + `src/homeserver/client_server.cpp` | Wall-clock rate limiter, lifted per-endpoint caps, per-user login cap, plumb `ClientRateLimitsConfig`, plumb module level filter into the runtime. |
| `include/merovingian/config/config.hpp` + `src/config/parser.cpp` | New `ClientRateLimitsConfig`, new `LogModulesConfig`. |
| `src/homeserver/auth_service.cpp` + `src/auth/session.cpp` + `src/auth/token.cpp` + `src/http/rate_limit.cpp` | Re-tag the 5 call sites with the severity-bearing helper. |
| `src/homeserver/admin_routes.cpp` (or wherever `/admin/audit` lives) | Add the `?category=…&since=…&event_type=…` filter. |
| `tests/unit/test_log_severity_routing.cpp` (new) | 5 BDD scenarios. |
| `tests/unit/test_rate_limit_wall_clock.cpp` (new) | 5 BDD scenarios. |

## BDD scenarios

### `tests/unit/test_log_severity_routing.cpp`

1. `log_diagnostic("event.name", {}, LogEventSeverity::debug)` →
   line lands at DEBUG, no audit row.
2. `log_diagnostic_audit("event.name", {}, LogEventSeverity::debug)`
   → no audit row (severity below warning).
3. `log_diagnostic_audit("event.name", {}, LogEventSeverity::warning)`
   → audit row appended with category/event_type/reason.
4. `SingleLog::set_module_log_level("http_server", LogLevel::info)`
   silences `log_diagnostic` lines that start with
   `http_server` when the runtime level is `debug`.
5. `set_default_log_level(LogLevel::info)` acts as the wildcard
   default for modules without an explicit entry.

### `tests/unit/test_rate_limit_wall_clock.cpp`

1. 20 successful registration probe+POST pairs in 60 s of simulated
   wall-clock time are allowed; the 21st 429s.
2. The bucket rolls over on wall-clock seconds, not on a request
   counter; advancing the injected `Clock` by 60 s resets the
   bucket.
3. Per-IP and per-user buckets are independent — one IP exhausting
   `/register` does not block a different IP from registering.
4. Per-user login cap of 5 / 60 s applies; the 6th `/login` for the
   same user from any IP 429s.
5. A new `ClientRateLimitsConfig` block in the runtime overrides
   the in-code defaults; e.g. `register_per_ip_max=3` → 4th
   registration 429s.

## Backwards compatibility

- Every existing `log_diagnostic(event, fields)` call continues to
  compile and behave exactly as today (the severity arg defaults to
  `LogEventSeverity::debug`).
- The new `log_diagnostic_audit` is opt-in: existing call sites are
  not changed mechanically; only the five high-signal failure sites
  listed in §3 are upgraded.
- `merovingian.conf` without the new `log_modules` or
  `ClientRateLimitsConfig` sections behaves exactly as today
  (default floor applied).
- The rate-limiter wall-clock rewrite changes the effective cap
  (5 / 64 reqs → 20 / 60s on `/register`), which **is** a behaviour
  change. Documented in the 0.5.0 changelog entry as a deliberate
  relaxation; previously the cap was a footgun.

## Open question: file logging

The original proposal included a `failures.log` companion sink. The
operator confirmed logs go to stdout, so a separate file sink adds
operational burden without a matching benefit. **No failures.log
sink is added in 0.5.0.** If operator demand for a separate
file destination later grows, it can be added as a follow-up
without changing this design.

## Sign-off

- Operator: the per-endpoint rate-limit caps (20/min per IP for
  `/register` and `/login`, 5/min per user for `/login`) and the
  restart-resets-counter behaviour.
- Branch: `feature/log-severity-and-failure-routing` off `main`
  (not off `fix/otk-signature-claim`).
- Version: 0.4.62 → 0.5.0 (feature, not a patch).
- PR target: `main`.
- Order: ship the OTK fix (already in PR #189) first; ship this
  feature after.
