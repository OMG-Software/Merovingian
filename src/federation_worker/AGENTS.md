# src/federation_worker/ — Federation Worker Process

The child-process side of the out-of-process federation worker, built as the
`merovingian-fed-worker` executable (`src/federation_worker/meson.build`). Spawning and
supervision (`WorkerSupervisor`, `WorkerPool`, `FederationProxy`) live in `src/homeserver/`;
this module is only what runs *inside* the worker once it has been exec'd.

The worker isolates untrusted inbound federation traffic from the client-server thread pool and,
because it is the process most exposed to hostile input, holds as little trust as possible
(ADR-0015, ADR-0078; `docs/architecture.md`, "Federation worker consistency model").

## Key files

| File | Responsibility |
|---|---|
| `main.cpp` | Entry point: parses argv, reads `--config`, validates the inherited IPC and IPC-key fds, applies worker hardening, runs the event loop |
| `ParsedWorkerArgs.cpp` | Parses `--config <path>`, `--ipc-fd <fd>`, and `--ipc-key-fd <fd>` (all required), plus `--shard <index>` (optional, default 0); anything else, the retired `--db-uri-fd` included, is refused (ADR-0736) |
| `IpcKeyFd.cpp` / `.hpp` | `read_ipc_auth_key`: reads the IPC auth key main wrote to the inherited key-fd, fail-closed on short/long/missing input; `clear_master_key_file`: empties the worker's config copy of `security.secrets.master_key_file` |
| `main.cpp` (Landlock step) | ADR-0062 part 3. Calls `platform::apply_worker_landlock()` before the worker seccomp filter and before `WorkerEventLoop` starts — see "Rules" item 3 below |
| `StoreReadGuard.cpp` | `StoreReadGuard`: the worker's reader-writer lock over its store (rule 6) |
| `RoomReloadCoalescer.cpp` | `RoomReloadCoalescer`: merges a room's `room_sync` notifications into a bounded number of reloads (rule 6, ADR-0623) |
| `WorkerRelayFrame.cpp` | `worker_relay_frame` / `relay_to_main`: the claim and key/profile query relay frames and their send, bound to the request being served (rule 12) |
| `WorkerDatabaseConfig.cpp` | `clear_database_location`: switches the worker's config copy to `database.backend=memory` and empties every database location (rule 2, ADR-0733) |
| `WorkerEventLoop.cpp` / `.hpp` | `WorkerEventLoop`: owns the `IpcChannel`, fills an in-memory store from main and starts a `HomeserverRuntime` on it with `TableLoadProfile::federation_worker`, reloads rooms and refreshes keys through main, wires federation callbacks to relay over IPC, runs the two request thread pools |

`WorkerEventLoop.hpp` sits next to its `.cpp` and is included with a bare relative include — the
one exception to the `merovingian/` include-path rule in `src/AGENTS.md`.

## Rules — non-negotiable

1. **The worker never holds the Matrix signing secret and never signs.** It starts its runtime with
   `RuntimeStartOptions::signing_disabled`, which installs `crypto::RefusingEd25519Provider` (every
   sign and verify request fails closed), and it does not ask main to sign: there is no
   `sign_request` frame ([ADR-0078](../../docs/adr/0078-the-federation-worker-never-signs.md),
   superseding the signing-oracle part of ADR-0015). Outbound requests are signed in main and reach the
   worker already signed; invites relay to main. Never reinstate a generic signing frame or a
   provider that forwards to main. The worker reads `--config`, but as of
   0.12.13 (finding N1, [ADR-0062](../../docs/adr/0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md))
   it never opens the operator master-key file either: main derives the IPC channel's auth key
   once and hands the worker only those 32 bytes over a second inherited pipe fd (`--ipc-key-fd`,
   read by `federation_worker::read_ipc_auth_key` in `IpcKeyFd.cpp`). `WorkerEventLoop::run()`
   then clears `security.secrets.master_key_file` on its own config copy
   (`federation_worker::clear_master_key_file`) before starting the runtime, so no later code
   path — reached today or added in the future — can open that file from inside the worker.
2. **The worker opens no database, on either backend (C44, [ADR-0733](../../docs/adr/0733-the-federation-worker-opens-no-database-main-sends-it-what-it-reads.md)).**
   A SHARED lock the worker held on main's SQLite file made every write in main wait its busy timeout and fail, and
   its PostgreSQL login could exhaust connections, hold main's migration advisory lock and pin the xmin horizon.
   `main.cpp` switches the worker's configuration copy to `database.backend=memory` and clears every database location
   (`federation_worker::clear_database_location`, `WorkerDatabaseConfig.cpp`) before it builds the Landlock rules, and
   `WorkerEventLoop::run()` clears its own copy again before it starts the runtime. The store is filled from main
   instead: `run()` starts the channel before the runtime, with the request handler parked behind a `DispatchGate`
   until the runtime exists, and `RuntimeStartOptions::fill_store` asks main for the room list (`room_list_request`)
   and then each room (`room_snapshot_request`, page by page through `ipc::RoomSnapshotAssembler`), one room at a
   time, before hydration. A room list main refuses stops the worker (the supervisor restarts it); a room main
   cannot send is logged and left out until its next `room_sync`, and reported to main as a `failed`
   `room_sync_result` of generation 0, so main serves the room meanwhile (ADR-0756). Main answers only under a permit it issued
   ([ADR-0735](../../docs/adr/0735-a-worker-may-have-main-read-a-room-only-under-a-permit-main-issued-and-only-once.md)).
   Never give the worker a database path, URI, descriptor or Landlock grant again, and never add a worker read that
   does not come through main. `RuntimeStartOptions::database_load_profile` stays
   `database::TableLoadProfile::federation_worker`: it switches on the key read-through below and skips main's
   start-up work. Main hands the worker no database credential: the PostgreSQL worker login, its two
   configuration keys and `--db-uri-fd` are retired, the keys refused at parse
   ([ADR-0736](../../docs/adr/0736-the-retired-worker-database-keys-are-refused-at-parse.md)).
3. **The worker restricts its own filesystem access with Linux Landlock (ADR-0062 part 3),
   applied before the worker seccomp filter and before anything below.** `main.cpp` calls
   `platform::apply_worker_landlock()` with the rules `platform::build_worker_landlock_rules()`
   returns, none of which comes from the database keys (rule 2), whatever the config names: a fixed set of
   best-effort OS-integration paths (CA trust store, resolver configuration, NSS/dynamic-linker
   library directories, timezone data), and never the database directory. The secret check runs
   against the operator's own configuration: the master key file, the database URI file, and TLS
   private keys are never granted.
   Landlock's three syscalls are not on the worker seccomp allowlist below, so this must run
   first. On a kernel without Landlock the worker refuses to start unless
   `federation.worker.allow_without_landlock=true`, which logs CRITICAL on every start; any other
   Landlock failure is always fatal regardless of that opt-out.
4. **The worker's own `PersistentStore` is a read-only snapshot for room-scoped federation reads —
   never the system of record.** `pdu_sink`, `membership_acceptor`, `invite_handler`, `edu_sink`,
   `one_time_keys_claim_provider`, `user_devices_provider`, `device_keys_query_provider`,
   `profile_query_provider`, `directory_query_provider` (an alias made after the worker started), `public_rooms_provider` (a directory that names no room and reads appservice registrations, ADR-0461) and `event_query_provider` all relay to main over IPC. Each was a
   shipped bug when it did not (worker-accepted joins and invites invisible to main, split-brain
   one-time-key claims, stale device and profile reads); see the comments above each override in
   `WorkerEventLoop.cpp`. `membership_template_provider` relays `make_join` (only) as
   `membership_template_ingest`: a restricted room's allow conditions name rooms another shard
   owns (R04, ADR-0184).
   The one table the worker refreshes on demand is `server_signing_keys`, and only for the public
   key of the server it is verifying: its `cached_pdu_key_lookup` and its resolver (built with
   `federation::KeyMirrorRefresh::on_miss`) both refresh on a miss (`HomeserverRuntime`'s
   `LocalDatabase::remote_signing_keys_read_through`, set from the `federation_worker` load profile),
   so a key main verified and cached is asked of main (`server_keys_request`, through `PersistentStore::remote_signing_key_source`) instead
   of being fetched again in front of the first PDU main already authenticated. Main answers from its
   in-memory table, public columns only, never a row that holds a secret, at most 256 rows
   (`database::public_signing_keys_of_server`); `database::refresh_remote_signing_keys` takes only the
   named server's rows without a secret from the answer. Do not widen either side and do not give main's
   resolver the same flag.
5. **`local_pool` and `relay_pool` stay separate.** `local_pool` (`federation.worker.threads`)
   serves endpoints answerable from the snapshot; `relay_pool` (`federation.worker.relay_threads`)
   serves endpoints that block on an IPC round trip or outbound HTTP.
   `federation::federation_endpoint_requires_main_relay` routes each request before a thread is
   committed, so slow relays cannot starve fast local reads.
6. **`room_sync` notifications run on `reload_pool`, never inline on the IPC dispatch thread, go through the
   `RoomReloadCoalescer` (ADR-0623), and reload through the `StoreReadGuard` (F-27, ADR-0360).** A
   notification for a room already scheduled costs nothing; the coalescer's header states the invariant a change must
   keep (a reload that starts after a notification was recorded sees its change). Hold no lock across a round. The reload
   (`StoreReadGuard::reload_room_from`) asks main for the room at the round's generation, with no lock held, and takes
   the guard's exclusive lock only to swap the room's rows in memory; every provider that reads the store
   (ACL, room version, state, state_ids, event_auth, get_missing_events, backfill, timestamp_to_event,
   hierarchy, the local make_leave/make_knock template) is wrapped by `wrap_store_readers` and holds the
   shared lock for its own call, returning values it owns. A relay transaction does NOT hold
   `runtime.mutex` across its round trips (`handle_federation_http_request` releases it before
   dispatch), so that mutex excludes nothing here. Wrap before the overrides that relay to main, never
   hold the lock across IPC, and copy anything a table lends you (state groups, state indexes, deferred
   PDU awaits) before releasing it. Running the reload on the dispatch thread would block every later
   frame behind the readers; see `docs/architecture.md`, "IPC reader/dispatch split".
7. **Never call `channel->stop()` from inside a request handler.** `stop()` joins the dispatch
   thread and a thread cannot join itself. On `"shutdown"`, signal a condition variable and let the
   worker's main thread call `stop()`.
8. **Drain every thread pool before stopping the IPC channel on shutdown.** An in-flight handler
   still needs the channel to send its response.
9. **The worker loads no application service registrations (ADR-0296).** It starts its runtime with
   `RuntimeStartOptions::load_appservices = false`: `runtime.appservices` stays empty and no
   sender user is created. A registration holds the `as_token` and `hs_token`, kept outside the
   worker's Landlock grants (it logged `cannot open appservice registration file` on every start
   when it tried), and everything that consults the registry runs in main. Never grant the worker
   the registration directory to make a handler work; relay the decision to main.
10. **Main believes only a signature-verified answer from this worker's outbound tunnel (F-43, ADR-0349).**
    The `outbound_http_request` handler executes a request main already signed, and main uses its reply only for the
    four backfill fetches (`OutboundAnswerTrust::signature_verified`); every other outbound call goes over main's own
    client. Do not move another call onto the tunnel here, and do not add a worker-to-main frame whose content main
    would act on without a signature check. The reply is validated in `WorkerPool::send_outbound_request`.
10. **The worker's ACL and policy view is advisory (F-21, F-24, ADR-0358, ADR-0359).** It holds no
   policy rules on either backend (ADR-0733), and learns of a room only when it owns
   its shard. Main judges the origin's rule and the room's ACL again on everything relayed, and the
   worker does not run the policy-server hook: the proxy asked it once before forwarding.

11. **A relayed EDU must be the one main verified in the request body (F-74, ADR-0395).** The `edu_sink` override
   relays the `content_json` string exactly as `parse_inbound_edu_envelope` received it, which is the canonical
   serialisation `federation::extract_transaction_edus` produces; main compares a digest of it with the digests of the
   verified `/send` body and refuses any other. Never re-serialise, normalise or edit the content before relaying, and
   never relay an EDU from a request other than the `/send` that carried it (`FedRequestParentScope`).

12. **A claim or key/profile query relay names the request it serves (GHSA-3p5v-vrg8-f545, ADR-0595).** The
   `one_time_keys_claim_provider`, `device_keys_query_provider`, `user_devices_provider` and `profile_query_provider`
   overrides send through `relay_to_main` (`WorkerRelayFrame.cpp`), which puts `current_fed_parent_request_id` in the
   frame and sends nothing when it is 0. They relay the argument the federation handler passed unchanged (the request
   body, or the user ID read by `WorkerRelayBinding.hpp` and `core::query_parameter`): main admits only a digest of
   that exact argument, once, for the verified request it forwarded. Never build one of these frames by hand: main's
   relay tests run against `worker_relay_frame`, so a hand-built frame is one no test has seen.

## Hardening

`main()` starts with `platform::ignore_sigpipe()` (HTTP-5; exits 1 on failure), then leaves main's session with
`setsid()` when the supervisor's `POSIX_SPAWN_SETSID` has not already done so, and exits 1 if it cannot: the worker
never holds the terminal of the shell that started the server, and its stdin is `/dev/null` (ADR-0731). No thread may exist
before the two calls below (ISO-1, [ADR-0082](../../docs/adr/0082-no-thread-may-start-before-process-hardening-seccomp-is-installed-with-tsync.md)):
the logger writes synchronously until `main.cpp` calls `SingleLog::instance().start_writers()`, which it
does only after both, so the logger's writer threads inherit the Landlock ruleset and the seccomp filter.
The worker filter is installed with `SECCOMP_FILTER_FLAG_TSYNC` as a second line of defence, but
Landlock has no thread-sync flag, so the ordering is what matters. Do not start a thread, or call
anything that does, above the hardening calls in `main.cpp`.

Before the event loop opens the database or starts threads, `main.cpp` first calls
`platform::apply_worker_landlock()` (ADR-0062 part 3; see Rules item 3 above), then
`platform::apply_worker_hardening()` (gated by `federation.worker.apply_hardening`, default
`true`), which applies in order, each fail-closed: the core-dump policy (`RLIMIT_CORE` 0 and
`PR_SET_DUMPABLE` 0), `PR_SET_NO_NEW_PRIVS`, the capability-bounding-set drop, and a worker seccomp profile that
denies `execve`/`execveat` (`clone`/`clone3` stay allowed because the worker runs thread pools).
`apply_worker_landlock()` sets `PR_SET_NO_NEW_PRIVS` on its own before `landlock_restrict_self()`, because it runs
whether or not `apply_hardening` is on. On platforms with no in-process equivalent,
`apply_worker_hardening()` fails closed — the worker refuses to start rather than run unsandboxed (ADR-0041).
ASan builds disable exit-time LeakSanitizer in the worker because the seccomp profile denies the `ptrace` it needs.

The worker filter also denies `kill`, `tkill` and `setrlimit`, allows `tgkill` only on the worker's
own thread group and `prlimit64` only to read its own limits (ISO-2,
[ADR-0112](../../docs/adr/0112-restrict-worker-signals-and-resource-limits.md)). Anything the worker
runs after `apply_worker_hardening()` must therefore not set an rlimit. In particular
`WorkerEventLoop::run()` passes `RuntimeStartOptions::process_hardening_applied_by_caller` (from
`federation.worker.apply_hardening`) so `start_runtime()` does not re-apply the main-process
hardening profile, whose `setrlimit(RLIMIT_CORE)` would kill the worker with `SIGSYS`. The test
suite sets `MEROVINGIAN_TEST_DISABLE_HARDENING`, which hides such a call from most tests;
`[federation-worker][seccomp]` in `tests/integration/test_federation_worker_flow.cpp` starts a real
worker under the filter and is the regression test for it.

## Testing

- `tests/unit/test_federation_worker_args.cpp` — argv parsing, including `--ipc-key-fd` validation and the refusal of
  the retired `--db-uri-fd` (tag `[args][c44]`)
- `tests/unit/test_federation_worker_ipc_key_fd.cpp` — `read_ipc_auth_key` / `clear_master_key_file` (tag `[worker_key_fd]`)
- `tests/unit/test_worker_table_load_profile.cpp` — `database::table_load_profile_includes`, the classification of
  every migration table, and the key pipe's empty-material refusal (tag `[worker_table_profile]`)
- `tests/unit/test_worker_event_loop.cpp` — `WorkerEventLoop` construction and `run()` lifecycle
- `tests/unit/test_worker_relay_frame.cpp` — `worker_relay_frame` and `relay_to_main` (tag `[relay-frame]`)
- `tests/unit/test_worker_hardening_threads.cpp` — forked real-kernel proof (tag `[worker_hardening]`) that a
  thread created before hardening is confined by TSYNC and that a logger that logged before hardening has
  created no thread, so its later writers inherit Landlock and seccomp; SKIPs with a message on kernels
  without seccomp or Landlock
- `tests/unit/test_worker_landlock.cpp` — `apply_worker_landlock` fail-closed paths with injected
  `LandlockHardeningOps`, `build_worker_landlock_rules` allowlist content, ABI rights downgrade,
  config parsing/reload classification, no database grant on either backend (tag `[c44][landlock-no-database]`),
  and a forked real-kernel enforcement scenario (tag `[worker_landlock]`)
- `tests/unit/test_worker_database_config.cpp` — `clear_database_location` leaves no database location on either
  backend (tag `[c44][worker-database-config]`), and the retired keys are refused at parse, by name
  (tag `[c44][retired-worker-database-keys]`)
- `tests/unit/test_sqlite_security_policy.cpp` — a landlocked child cannot open main's SQLite file for reading or
  writing (tag `[iso4_landlock][c44]`, real kernel)
- `tests/unit/test_store_read_guard.cpp` — `StoreReadGuard`, including `reload_room_from` holding no store lock
  across main's read (tag `[c44][reload-from]`)
- `tests/unit/test_worker_room_snapshot_fill.cpp` — filling a store from main's snapshots and refreshing the key
  mirror from main's answer (tags `[c44][snapshot-fill]`, `[c44][key-source]`)
- `tests/integration/test_federation_worker_flow.cpp` — event loop and IPC relay behaviour; a real worker on a
  SQLite server opens no database and, stopped with SIGSTOP, cannot block main's writes (tag
  `[c44][worker-no-database]`)

## Key docs

- `docs/architecture.md` — "Federation worker consistency model", "IPC reader/dispatch split"
- `docs/hardening.md` — "Out-of-process federation worker IPC security"
- `docs/threat-model.md` — "Operator master key reachable from the federation worker"
- [ADR-0015](../../docs/adr/0015-keep-the-signing-secret-out-of-the-federation-worker.md) ·
  [ADR-0078](../../docs/adr/0078-the-federation-worker-never-signs.md) ·
  [ADR-0041](../../docs/adr/0041-refuse-to-start-the-federation-worker-unsandboxed.md) ·
  [ADR-0042](../../docs/adr/0042-spawn-the-federation-worker-with-a-minimal-environment.md) ·
  [ADR-0062](../../docs/adr/0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md)
