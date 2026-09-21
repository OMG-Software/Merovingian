# Federation worker holds no secret files; secrets arrive over inherited fds

* Status: accepted
* Deciders: James Chapman
* Date: 2026-09-21

Technical Story: 0.12.13 security audit, Critical/High findings — finding N1
(the out-of-process federation worker can recover the operator master key,
and from it the server signing secret and access-token HMAC keys, even though
it never uses them today).

## Context and Problem Statement

The federation worker (`merovingian-fed-worker`) is a separate, more exposed
process specifically so that a compromise of it does not hand an attacker the
Matrix signing secret (ADR-0015). Before this change it still opened the
*operator master-key file* itself, at startup (`WorkerEventLoop::run()`
called `crypto::load_master_key_material` then `crypto::derive_ipc_auth_key`)
so it could authenticate the IPC handshake with main. That file is the root
secret every other protected key is derived from: the secret-box key that
encrypts `server_signing_keys.secret_key` at rest
(`crypto::signing_secret_box_key`) and the v3/v4 access-token HMAC keys
(`crypto::derive_token_hmac_key[_v3]`). No worker-reachable code path actually
calls those derivations today (`GET /_matrix/key/v2/server` and
`GET /_matrix/federation/v1/openid/userinfo` are always served on main by
`FederationProxy::handle`, and the worker always installs a non-null
`crypto_provider` `signing_override`, so `ensure_runtime_server_signing_key`
is never reached inside it) — but the worker had the file open on disk with
no code-level reason to, which is worse than needed for a process whose whole
purpose is to hold as little trust as possible, and one bug in that reasoning
(a future worker code path that calls one of those derivations, or an
operator-visible route accidentally proxied to the worker) would silently
turn "the worker can't reach it" into "the worker already had it".

It also started a full `HomeserverRuntime` with the *same* database
credentials as main and no filesystem sandbox beyond seccomp (which does not
restrict file paths, only syscalls), so removing the master-key file access
alone does not make the worker fully untrusted — it closes one of three
related gaps.

## Decision Drivers

* A process whose entire purpose is holding minimal trust should not hold a
  root secret it has no code-level need for, even if no current code path
  uses it.
* Whatever replaces file access must not weaken the existing mutual
  authentication the IPC key already provides (ADR unnumbered, #318) — the
  worker must still prove it holds *something* main issued it, not accept an
  unauthenticated channel.
* The fix must not require the worker to re-derive anything from a hash of a
  file it should not be reading; it must receive the already-derived key
  material, verifiably, exactly once.
* Future parts (separate DB credential; Landlock) depend on the same delivery
  mechanism (inherited fd at spawn) established here, so the mechanism should
  generalise rather than being a one-off pipe hack.

## Considered Options — overall 3-part design

This finding is fixed in three parts, landing as separate commits/PRs. This
ADR records the full design; parts 1 and 2 have shipped as of this record's
last update (part 2: 0.12.13, same branch).

1. **(This ADR, shipped 0.12.13) Secrets arrive over inherited fds, not
   files.** Main derives the IPC auth key once and hands the worker only
   those 32 bytes over a second inherited pipe fd at spawn time. The worker
   never opens the master-key file.
2. **(Shipped 0.12.13, this update) A separate, least-privilege worker
   database login.** A second PostgreSQL role
   (`federation.worker.database_uri_file`), read by main and handed to the
   worker the same way (an inherited fd, not a file the worker opens), whose
   grants exclude `SELECT` on `server_signing_keys` and the other
   credential-bearing tables `database::table_load_profile_includes`
   excludes.
3. **(Planned) Linux Landlock filesystem restriction.** The worker calls
   `landlock_restrict_self` to deny filesystem access outside what it
   genuinely needs (its own SQLite file, if any; nothing else). If the
   running kernel lacks Landlock support, the worker refuses to start unless
   the operator sets `federation.worker.allow_without_landlock=true`, which
   logs CRITICAL on every start — mirroring the fail-closed seccomp policy in
   ADR-0041. Until this lands, a worker compromised through a memory-safety
   bug (not merely one abusing an intentional file-open) could still open the
   master-key file directly off disk despite no code path asking it to.

### Options considered and rejected, for part 1

* **Status quo: worker reads the master key file itself.** Rejected — this is
  the finding; see Context above.
* **A separate on-disk IPC key file**, written by main and read by the worker
  by path (`federation.worker.ipc_key_file` or similar). Rejected: this still
  leaves a secret sitting on disk with a path the worker's config carries,
  reintroducing a smaller version of the same class of problem (a file the
  worker can be tricked into reading again, e.g. after a config-reload bug,
  or that persists across a crash for another process to read). An inherited
  fd has no path, cannot be reopened after the handshake, and is closed
  automatically if the worker never starts (nothing to clean up).
* **Pass the key as a command-line argument or environment variable.** Rejected
  outright: both are visible to any other process on the host via `/proc/<pid>/cmdline`
  or `/proc/<pid>/environ` (root, or same-UID with appropriate permissions),
  which is a strictly worse exposure than an fd only the two processes involved
  ever hold. ADR-0042 already rejects environment variables for this exact
  reason for the worker's environment generally.
* **SET ROLE-based database separation instead of a second login (bears on
  part 2, recorded here since it was evaluated alongside this finding).**
  Rejected: a session that can `SET ROLE` to a restricted role can also
  `RESET ROLE` back to the login role that granted it, so a compromised
  worker holding the *original* login credential gains nothing from a
  restricted role it can trivially undo. Only a distinct login credential
  the worker process never has in the first place is a real boundary.
* **Best-effort Landlock (log a warning and continue if unavailable), instead
  of fail-closed (bears on part 3, recorded here for the same reason).**
  Rejected for the same reason ADR-0041 rejected best-effort seccomp: an
  operator who cannot tell "sandboxed" from "silently unsandboxed" from the
  logs will not notice until it matters. The explicit
  `allow_without_landlock=true` escape hatch keeps old kernels usable without
  making the gap silent.

## Decision Outcome

Chosen option for part 1: **secrets arrive over inherited fds, not files.**

`homeserver::WorkerPool`'s constructor derives the IPC auth key once, from
the operator master-key file, for the whole pool (not once per shard/restart).
`homeserver::WorkerSupervisor::spawn_and_connect` — reused for every spawn and
every automatic restart — creates a `pipe2(O_CLOEXEC)` pipe, writes exactly
the derived key bytes into it and closes its own write end
(`homeserver::make_worker_key_pipe`). The read end **stays `FD_CLOEXEC` in
main**: main is multithreaded, and clearing the flag in the parent would let
any concurrent spawn (another shard's restart, the thumbnail decoder) inherit
the pipe carrying the key. Instead a `posix_spawn_file_actions_adddup2` places
it at the fixed `kWorkerIpcKeyFd` (4) in the child, which clears `FD_CLOEXEC`
on the child's copy only, and `--ipc-key-fd 4` is passed alongside the
existing `--ipc-fd 3`. The helper keeps the source fd off both fixed numbers,
so the dup2 can neither be clobbered by the ipc socket's dup2 nor degenerate
into a same-fd dup2 (which some libcs treat as a no-op that leaves the flag set).
The worker (`federation_worker::read_ipc_auth_key`, `src/federation_worker/ipc_key_fd.cpp`)
reads exactly that many bytes, requires EOF immediately afterward (rejecting
a short or long write rather than truncating or padding it), and closes the
fd. `WorkerEventLoop::run()` then calls `federation_worker::clear_master_key_file`
on its own in-memory config copy — emptying `security.secrets.master_key_file`
— before calling `homeserver::start_runtime()`, so no runtime code path
inside the worker (today's or a future one) has a path string to pass to
`crypto::load_master_key_material` even if it tried.

Key bytes live in `core::SecretBuffer` on the main side (mlocked, zeroised);
the intermediate `crypto::IpcAuthKey` value used to build the pipe write and
the per-process `IpcChannel` is itself self-zeroising (its destructor calls
`sodium_memzero`), consistent with `core/AGENTS.md`.

### Positive Consequences

* The worker process, at the OS level, no longer has the master-key file
  open at any point in its lifetime — a compromise that reads worker process
  memory or inspects its open file descriptors finds only a derived,
  single-purpose key, never the root secret.
* The change generalises: parts 2 and 3 reuse "main reads/derives the
  sensitive thing once and hands the worker only what it needs over an
  inherited fd" as the same pattern, rather than inventing a new mechanism
  per finding.
* `WorkerPool` deriving the key once instead of `WorkerSupervisor` deriving
  it on every spawn/restart also removes N-1 redundant master-key-file reads
  and `sodium_mlock`/`munlock` pairs for an N-shard, M-restart deployment.

### Negative Consequences

* Two inherited fds to manage per worker spawn instead of one, including a
  fd-numbering hazard (the pipe's read end could coincidentally land on the
  fixed `kWorkerIpcFd` number) that `spawn_and_connect` now defends against
  explicitly, mirroring the pre-existing defence for `server_fd`.
* This part alone does not make the worker fully untrusted with respect to
  the master key's *effects*: it still shares main's database credentials
  (part 2 closes this) and has no filesystem sandbox beyond seccomp's syscall
  restrictions (part 3 closes this). See docs/threat-model.md, "Operator
  master key reachable from the federation worker", for the running record of
  which gap is closed as of a given version.

## Decision Outcome, part 2

Chosen option for part 2: **a separate, least-privilege PostgreSQL login,
delivered the same inherited-fd way as part 1, plus a load profile so the
worker never hydrates the excluded material into memory regardless of which
credential it holds.**

`homeserver::worker_supervisor.cpp`'s `make_worker_key_pipe` is generalised
into `make_worker_secret_pipe(secret, reserved_fds)` — the same construction
(pipe2(O_CLOEXEC), stays FD_CLOEXEC in the multithreaded parent, relocated
past every reserved fd via `F_DUPFD_CLOEXEC` so it can never land on one) now
parameterised over an arbitrary set of reserved child fd numbers instead of
the two part 1 hardcoded. `make_worker_db_uri_pipe` is the new caller,
reserving `kWorkerIpcFd` (3), `kWorkerIpcKeyFd` (4), and the new
`kWorkerDbUriFd` (5); `make_worker_key_pipe` itself is unchanged in name,
signature, and behaviour. `WorkerPool::WorkerPool` reads
`federation.worker.database_uri_file` once (mirroring the master-key-material
derivation immediately above it) and hands each `WorkerSupervisor` its own
`core::SecretBuffer` copy; `spawn_and_connect` passes `--db-uri-fd <n>` on
argv and adds a third `adddup2` file action, but **only when a separate URI
actually applies** — a SQLite backend or the
`allow_shared_database_credentials=true` opt-out mean neither the flag nor
the pipe exist at all, so the degraded mode is explicit in the child's argv,
not an accidental silent fallback. The worker
(`federation_worker::read_worker_database_uri`) reads until EOF — the URI has
no fixed length, unlike the 32-byte auth key — bounded to 4096 bytes,
rejecting empty or oversized results, and
`federation_worker::apply_worker_database_uri` sets the worker's own config
copy's `database.worker_conninfo_override` and clears
`uri_file`/`runtime_role`/`migration_role`, so the restricted login connects
directly with its own grants and never attempts a `SET ROLE` onto roles it
was never made a member of.

Independently, `database::TableLoadProfile::federation_worker`
(`RuntimeStartOptions::database_load_profile`, set unconditionally by
`WorkerEventLoop::run()`) makes `open_postgresql_persistent_store`'s row
loader skip `server_signing_keys`, `users`, `access_tokens`,
`refresh_tokens`, `login_tokens`, `openid_tokens`, and `account_threepids` —
see `database::table_load_profile_includes`,
`include/merovingian/database/persistent_store.hpp`. This is deliberately a
*second, independent* mechanism from the separate login: it means the worker
never pulls that material into its own process memory even in the
`allow_shared_database_credentials=true` degraded mode, and it is what makes
the separate role's restricted grants actually *usable* — without it, the
row loader's unconditional `SELECT * FROM server_signing_keys` would make
the worker fail to start under a role that cannot read that table.

### Options considered and rejected, for part 2

* **SET ROLE-based database separation instead of a second login.** Already
  rejected above (recorded alongside part 1's own rejected options, since it
  was evaluated at the same time): a session that can `SET ROLE` to a
  restricted role can also `RESET ROLE` back to the login role that granted
  it, so a compromised worker holding the *original* login credential gains
  nothing from a restricted role it can trivially undo.
* **Grant the worker role broad SELECT and rely only on the load profile to
  protect `server_signing_keys`.** Rejected: the load profile is enforced
  entirely in this project's own C++ code, not by PostgreSQL. A future bug
  that constructs `RuntimeStartOptions` without setting
  `database_load_profile` (a new worker code path, a test harness, an
  embedder) would silently fall back to `TableLoadProfile::full` and load the
  secret anyway — the database-level `REVOKE` in
  `provision-federation-worker-role.sql` is what makes that failure mode
  impossible rather than merely unlikely. The two mechanisms are
  deliberately redundant, not substitutes for each other.
* **A single positive allowlist of tables the worker may read, enumerated by
  name in the GRANT script, instead of GRANT-ALL-then-REVOKE.** Rejected as
  the SQL-authoring approach: `provision-federation-worker-role.sql` grants
  `SELECT` on `ALL TABLES IN SCHEMA public` (plus `ALTER DEFAULT PRIVILEGES`
  for future tables) and then `REVOKE`s the seven excluded ones, the same
  shape `provision-roles.sql` already uses for `:runtime_role`. An allowlist
  would need updating for every future non-secret table a migration adds;
  the chosen shape needs updating only when a *new secret-bearing* table is
  added, which is also exactly when `table_load_profile_includes` needs a
  matching change — one trigger for both required edits, not two dissimilar
  ones.
* **Narrow the C++ load profile to the exact minimum set of tables each
  worker federation route reads, instead of excluding only the seven
  clearly-secret tables.** Considered, not chosen for this part: a precise
  per-route allowlist would be strictly smaller, but deriving it correctly
  requires tracing every non-relayed federation route
  (`make_join`/`make_leave`/`make_knock`, backfill, `query`/`directory`,
  `state`, `state_ids`, `get_missing_events`, hierarchy) against every table
  it might touch, with a wrong exclusion silently breaking worker
  functionality rather than failing loudly. Excluding only the tables that
  are unambiguously secret-bearing (and that no worker code path reads,
  since every actual read of that data is relayed to main over IPC — see
  `src/federation_worker/AGENTS.md` rule 3) is conservative but correct by
  construction, and closes the specific finding (recovering the signing
  secret and other credentials) without the risk of a functional regression.
  Narrowing further remains available as a future hardening step.
* **Grant `INSERT`/`UPDATE`/`DELETE` on the included tables, matching
  `:runtime_role`'s own DML grants.** Rejected: the worker's own
  `PersistentStore` is a read-only snapshot for room-scoped federation
  reads, never the system of record (`src/federation_worker/AGENTS.md` rule
  3) — every write the worker's federation routes need is relayed to main
  over IPC. `provision-federation-worker-role.sql` grants `SELECT` only,
  strictly less than `:runtime_role`.

### Positive Consequences, part 2

* A PostgreSQL-backed worker compromised through anything short of arbitrary
  filesystem access (part 3's remaining gap) cannot read
  `server_signing_keys.secret_key`, `access_tokens.token_hash`, or the other
  five excluded tables via SQL at all — the database itself refuses the
  query, independent of what this project's own code does or fails to do.
* The load profile is backend-agnostic and applies even in the
  `allow_shared_database_credentials=true` degraded mode: a worker sharing
  main's login still never pulls the excluded tables into its own process
  memory, narrowing what a memory-disclosure bug in the worker can expose
  even without a separate role provisioned.
* The generalised `make_worker_secret_pipe` means part 3, if it ever needs to
  hand the worker a third kind of secret material over an inherited fd,
  reuses the same reserved-fd-set parameterisation rather than a fourth
  bespoke pipe helper.

### Negative Consequences, part 2

* A third inherited fd and a third `posix_spawn_file_actions_adddup2` to
  manage per worker spawn, conditionally present depending on config —
  slightly more branching in `spawn_and_connect` than a fd that is always
  passed.
* `table_load_profile_includes` (C++) and `provision-federation-worker-role
  .sql`'s `REVOKE` list are two separate places that must be kept in sync by
  hand; nothing enforces this today beyond the cross-references each leaves
  in its own comments and in `docs/database-persistence.md`.
* SQLite deployments get no role-level improvement from this part — a single
  shared file offers no boundary to separate — and the load profile there
  reduces (but does not eliminate: the file itself remains fully readable by
  the worker process) how much credential material sits resident in worker
  memory. See docs/threat-model.md.

## Links

* [ADR-0015](0015-keep-the-signing-secret-out-of-the-federation-worker.md) — the
  signing-secret analogue of this decision; not superseded by this ADR, since
  it addresses a different secret (the signing key, delegated via IPC
  sign-request/sign-response, never handed to the worker in any form) via a
  different mechanism (a signing oracle, not a one-shot key handoff).
* [ADR-0041](0041-refuse-to-start-the-federation-worker-unsandboxed.md) — the
  fail-closed precedent part 3's Landlock gate follows.
* [ADR-0042](0042-spawn-the-federation-worker-with-a-minimal-environment.md) —
  established that secrets must not reach the worker via environment
  variables; this ADR extends the same reasoning to command-line arguments
  and to files the worker would otherwise open by path.
* `docs/threat-model.md`, "Operator master key reachable from the federation
  worker"
* `docs/hardening.md`, "Out_of_process federation worker IPC security"
* `docs/crypto-boundary.md`
* `docs/database-persistence.md`, "Federation worker least-privilege role"
  (part 2)
* `packaging/postgresql/provision-federation-worker-role.sql` (part 2)
