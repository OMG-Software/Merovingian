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
| `main.cpp` | Entry point: parses argv, reads `--config`, validates the inherited IPC fd, applies worker hardening, runs the event loop |
| `args.cpp` | Parses `--config <path>` and `--ipc-fd <fd>` (both required) and `--shard <index>` (optional, default 0) |
| `worker_event_loop.cpp` / `.hpp` | `WorkerEventLoop`: owns the `IpcChannel`, starts a `HomeserverRuntime`, wires federation callbacks to relay over IPC, runs the two request thread pools |

`worker_event_loop.hpp` sits next to its `.cpp` and is included with a bare relative include — the
one exception to the `merovingian/` include-path rule in `src/AGENTS.md`.

## Rules — non-negotiable

1. **The worker never holds the Matrix signing secret.** All Ed25519 signing is delegated to
   main through `ipc::IpcEd25519Provider` (ADR-0015). The worker reads `--config` and the master
   key file only to derive the IPC authentication key, never the signing key.
2. **The worker's own `PersistentStore` is a read-only snapshot for room-scoped federation reads —
   never the system of record.** `pdu_sink`, `membership_acceptor`, `invite_handler`, `edu_sink`,
   `one_time_keys_claim_provider`, `user_devices_provider`, `device_keys_query_provider`,
   `profile_query_provider` and `event_query_provider` all relay to main over IPC. Each was a
   shipped bug when it did not (worker-accepted joins and invites invisible to main, split-brain
   one-time-key claims, stale device and profile reads); see the comments above each override in
   `worker_event_loop.cpp`.
3. **`local_pool` and `relay_pool` stay separate.** `local_pool` (`federation.worker.threads`)
   serves endpoints answerable from the snapshot; `relay_pool` (`federation.worker.relay_threads`)
   serves endpoints that block on an IPC round trip or outbound HTTP.
   `federation::federation_endpoint_requires_main_relay` routes each request before a thread is
   committed, so slow relays cannot starve fast local reads.
4. **`room_sync` notifications run on `local_pool`, never inline on the IPC dispatch thread.**
   `database::reload_room` needs `runtime.mutex`, which a `relay_pool` transaction may hold across
   its own round trip to main; running it on the dispatch thread risks the reader/dispatch
   deadlock described in `docs/architecture.md`, "IPC reader/dispatch split".
5. **Never call `channel->stop()` from inside a request handler.** `stop()` joins the dispatch
   thread and a thread cannot join itself. On `"shutdown"`, signal a condition variable and let the
   worker's main thread call `stop()`.
6. **Drain both thread pools before stopping the IPC channel on shutdown.** An in-flight handler
   still needs the channel to send its response.

## Hardening

Before the event loop opens the database or starts threads, `main.cpp` calls
`platform::apply_worker_hardening()` (gated by `federation.worker.apply_hardening`, default
`true`): `PR_SET_NO_NEW_PRIVS`, capability drop, and a worker seccomp profile that denies
`execve`/`execveat` (`clone`/`clone3` stay allowed because the worker runs thread pools). On
platforms with no in-process equivalent this fails closed — the worker refuses to start rather
than run unsandboxed (ADR-0041). ASan builds disable exit-time LeakSanitizer in the worker because
the seccomp profile denies the `ptrace` it needs.

## Testing

- `tests/unit/test_federation_worker_args.cpp` — argv parsing
- `tests/integration/test_federation_worker_flow.cpp` — event loop and IPC relay behaviour

## Key docs

- `docs/architecture.md` — "Federation worker consistency model", "IPC reader/dispatch split"
- `docs/hardening.md` — "Out_of_process federation worker IPC security"
- [ADR-0015](../../docs/adr/0015-keep-the-signing-secret-out-of-the-federation-worker.md) ·
  [ADR-0041](../../docs/adr/0041-refuse-to-start-the-federation-worker-unsandboxed.md) ·
  [ADR-0042](../../docs/adr/0042-spawn-the-federation-worker-with-a-minimal-environment.md)
