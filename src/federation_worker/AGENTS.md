# src/federation_worker/ — Federation Worker Process

The child-process side of the out-of-process federation worker, built as the
`merovingian-fed-worker` executable (`src/federation_worker/meson.build`). Spawning and
supervision (`WorkerSupervisor`, `WorkerPool`, `FederationProxy`) live in `src/homeserver/`;
this module is only what runs *inside* the worker once it has been exec'd.

The worker isolates untrusted inbound federation traffic from the client-server thread pool and,
because it is the process most exposed to hostile input, holds as little trust as possible
(ADR-0015; `docs/architecture.md`, "Federation worker consistency model").

## Key files

| File | Responsibility |
|---|---|
| `main.cpp` | Entry point: parses argv, reads `--config`, validates the inherited IPC, IPC-key, and (when present) db-uri fds, applies worker hardening, runs the event loop |
| `args.cpp` | Parses `--config <path>`, `--ipc-fd <fd>`, and `--ipc-key-fd <fd>` (all required), plus `--shard <index>` and `--db-uri-fd <fd>` (both optional, default absent/0) |
| `ipc_key_fd.cpp` / `.hpp` | `read_ipc_auth_key`: reads the IPC auth key main wrote to the inherited key-fd, fail-closed on short/long/missing input; `clear_master_key_file`: empties the worker's config copy of `security.secrets.master_key_file` |
| `db_uri_fd.cpp` / `.hpp` | ADR-0062 part 2. `read_worker_database_uri`: reads a separate, least-privilege database connection URI from the inherited db-uri-fd until EOF, fail-closed on empty/oversized (>4096 bytes) input; `apply_worker_database_uri`: sets the worker's config copy's `database.worker_conninfo_override` and clears `uri_file`/`runtime_role`/`migration_role` |
| `main.cpp` (Landlock step) | ADR-0062 part 3. Calls `platform::apply_worker_landlock()` before the worker seccomp filter and before `WorkerEventLoop` starts — see "Rules" item 3 below |
| `worker_event_loop.cpp` / `.hpp` | `WorkerEventLoop`: owns the `IpcChannel`, starts a `HomeserverRuntime` with `TableLoadProfile::federation_worker`, wires federation callbacks to relay over IPC, runs the two request thread pools |

`worker_event_loop.hpp` sits next to its `.cpp` and is included with a bare relative include — the
one exception to the `merovingian/` include-path rule in `src/AGENTS.md`.

## Rules — non-negotiable

1. **The worker never holds the Matrix signing secret.** All Ed25519 signing is delegated to
   main through `ipc::IpcEd25519Provider` (ADR-0015). The worker reads `--config`, but as of
   0.12.13 (finding N1, [ADR-0062](../../docs/adr/0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md))
   it never opens the operator master-key file either: main derives the IPC channel's auth key
   once and hands the worker only those 32 bytes over a second inherited pipe fd (`--ipc-key-fd`,
   read by `federation_worker::read_ipc_auth_key` in `ipc_key_fd.cpp`). `WorkerEventLoop::run()`
   then clears `security.secrets.master_key_file` on its own config copy
   (`federation_worker::clear_master_key_file`) before starting the runtime, so no later code
   path — reached today or added in the future — can open that file from inside the worker.
2. **The worker never connects to a PostgreSQL database with main's own login (ADR-0062
   part 2).** A separate, least-privilege role's connection URI (`federation.worker.
   database_uri_file`, provisioned by `packaging/postgresql/provision-federation-worker-role.sql`)
   is delivered the same way as the IPC auth key — a third inherited pipe fd (`--db-uri-fd`,
   read by `federation_worker::read_worker_database_uri` in `db_uri_fd.cpp`) — never a file the
   worker opens. `federation_worker::apply_worker_database_uri` clears the worker's config
   copy's `database.uri_file`/`runtime_role`/`migration_role` at the same time, so the worker's
   restricted login connects directly with its own grants and never attempts a `SET ROLE` onto
   roles it was never made a member of. Independently, `RuntimeStartOptions::
   database_load_profile` is always set to `database::TableLoadProfile::federation_worker` in
   `WorkerEventLoop::run()`: the worker never pulls `server_signing_keys` and the other
   credential-bearing tables `database::table_load_profile_includes` excludes into its own
   process memory, regardless of which credential it authenticated with. See
   `docs/database-persistence.md`, "Federation worker least-privilege role". `database.
   backend=sqlite` offers no role to separate (a single shared file) — the worker keeps
   opening the same file there; the load profile is that backend's only protection.
3. **The worker restricts its own filesystem access with Linux Landlock (ADR-0062 part 3),
   applied before the worker seccomp filter and before anything below.** `main.cpp` calls
   `platform::apply_worker_landlock()` with the rules `platform::build_worker_landlock_rules()`
   derives from the worker's own config copy — the SQLite database directory (read-write,
   required, when `database.backend=sqlite`) plus a fixed set of best-effort OS-integration paths
   (CA trust store, resolver configuration, NSS/dynamic-linker library directories, timezone
   data). The master key file, both database URI files, and TLS private keys are never granted.
   Landlock's three syscalls are not on the worker seccomp allowlist below, so this must run
   first. On a kernel without Landlock the worker refuses to start unless
   `federation.worker.allow_without_landlock=true`, which logs CRITICAL on every start; any other
   Landlock failure is always fatal regardless of that opt-out.
4. **The worker's own `PersistentStore` is a read-only snapshot for room-scoped federation reads —
   never the system of record.** `pdu_sink`, `membership_acceptor`, `invite_handler`, `edu_sink`,
   `one_time_keys_claim_provider`, `user_devices_provider`, `device_keys_query_provider`,
   `profile_query_provider` and `event_query_provider` all relay to main over IPC. Each was a
   shipped bug when it did not (worker-accepted joins and invites invisible to main, split-brain
   one-time-key claims, stale device and profile reads); see the comments above each override in
   `worker_event_loop.cpp`.
5. **`local_pool` and `relay_pool` stay separate.** `local_pool` (`federation.worker.threads`)
   serves endpoints answerable from the snapshot; `relay_pool` (`federation.worker.relay_threads`)
   serves endpoints that block on an IPC round trip or outbound HTTP.
   `federation::federation_endpoint_requires_main_relay` routes each request before a thread is
   committed, so slow relays cannot starve fast local reads.
6. **`room_sync` notifications run on `local_pool`, never inline on the IPC dispatch thread.**
   `database::reload_room` needs `runtime.mutex`, which a `relay_pool` transaction may hold across
   its own round trip to main; running it on the dispatch thread risks the reader/dispatch
   deadlock described in `docs/architecture.md`, "IPC reader/dispatch split".
7. **Never call `channel->stop()` from inside a request handler.** `stop()` joins the dispatch
   thread and a thread cannot join itself. On `"shutdown"`, signal a condition variable and let the
   worker's main thread call `stop()`.
8. **Drain both thread pools before stopping the IPC channel on shutdown.** An in-flight handler
   still needs the channel to send its response.

## Hardening

Before the event loop opens the database or starts threads, `main.cpp` first calls
`platform::apply_worker_landlock()` (ADR-0062 part 3; see Rules item 3 above), then
`platform::apply_worker_hardening()` (gated by `federation.worker.apply_hardening`, default
`true`): `PR_SET_NO_NEW_PRIVS`, capability drop, and a worker seccomp profile that denies
`execve`/`execveat` (`clone`/`clone3` stay allowed because the worker runs thread pools). On
platforms with no in-process equivalent this fails closed — the worker refuses to start rather
than run unsandboxed (ADR-0041). ASan builds disable exit-time LeakSanitizer in the worker because
the seccomp profile denies the `ptrace` it needs.

## Testing

- `tests/unit/test_federation_worker_args.cpp` — argv parsing, including `--ipc-key-fd` and `--db-uri-fd` validation
- `tests/unit/test_federation_worker_ipc_key_fd.cpp` — `read_ipc_auth_key` / `clear_master_key_file` (tag `[worker_key_fd]`)
- `tests/unit/test_worker_db_uri.cpp` — config validation matrix, `--db-uri-fd` argv parsing, `read_worker_database_uri`,
  `apply_worker_database_uri`, `database::table_load_profile_includes`, and the generalized worker secret pipe
  (tag `[worker_db_uri]`)
- `tests/unit/test_worker_event_loop.cpp` — `WorkerEventLoop` construction and `run()` lifecycle
- `tests/unit/test_worker_landlock.cpp` — `apply_worker_landlock` fail-closed paths with injected
  `LandlockHardeningOps`, `build_worker_landlock_rules` allowlist content, ABI rights downgrade,
  config parsing/reload classification, and a forked real-kernel enforcement scenario (tag
  `[worker_landlock]`)
- `tests/integration/test_federation_worker_flow.cpp` — event loop and IPC relay behaviour
- `tests/integration/test_postgresql_persistence_flow.cpp` — the `federation_worker` load-profile scenario against a
  live PostgreSQL role lacking `SELECT` on `server_signing_keys` (gated by
  `MEROVINGIAN_TEST_POSTGRESQL_WORKER_ROLE`; skipped without a live PostgreSQL test environment)

## Key docs

- `docs/architecture.md` — "Federation worker consistency model", "IPC reader/dispatch split"
- `docs/hardening.md` — "Out-of-process federation worker IPC security"
- `docs/threat-model.md` — "Operator master key reachable from the federation worker"
- [ADR-0015](../../docs/adr/0015-keep-the-signing-secret-out-of-the-federation-worker.md) ·
  [ADR-0041](../../docs/adr/0041-refuse-to-start-the-federation-worker-unsandboxed.md) ·
  [ADR-0042](../../docs/adr/0042-spawn-the-federation-worker-with-a-minimal-environment.md) ·
  [ADR-0062](../../docs/adr/0062-federation-worker-holds-no-secret-files-secrets-arrive-over-inherited-fds.md)
