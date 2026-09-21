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
3. **(Shipped 0.12.13, this update) Linux Landlock filesystem restriction.**
   The worker calls `landlock_restrict_self` to deny filesystem access
   outside what it genuinely needs (its own SQLite database directory, if
   any, plus a fixed set of best-effort OS-integration paths; nothing else —
   never the master-key file, either database URI file, or TLS private
   keys). If the running kernel lacks Landlock support, the worker refuses to
   start unless the operator sets
   `federation.worker.allow_without_landlock=true`, which logs CRITICAL on
   every start — mirroring the fail-closed seccomp policy in ADR-0041.
   Before this landed, a worker compromised through a memory-safety bug (not
   merely one abusing an intentional file-open) could still open the
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
loader an **allowlist**: `database::federation_worker_table_allowlist`
(`include/merovingian/database/persistent_store.hpp`) names exactly nine
tables — `rooms`, `membership`, `current_state`, `events`, `event_edges`,
`event_auth`, `event_signatures`, `room_aliases`, and (column-restricted)
`server_signing_keys` — derived by tracing every non-relayed
`FederationRuntimeState` callback to the `PersistentStore` field it actually
reads; every table absent from the array is excluded, so a future
migration's new table is unreadable by the worker until someone adds it
deliberately. See `docs/database-persistence.md`, "Federation worker
least-privilege role", for the full per-table citation and the complete
classification of all 54 tables `migrations/*.sql` creates. This is
deliberately a *second, independent* mechanism from the separate login: it
means the worker never pulls unlisted material into its own process memory
even in the `allow_shared_database_credentials=true` degraded mode, and it
is what makes the separate role's restricted grants actually *usable* —
without it, the row loader's unconditional `SELECT` statements for every
other table would make the worker fail to start under a role that cannot
read them.

`server_signing_keys` needed a column-level answer, not a table-level one:
the worker's remote-key cache genuinely reads and writes *other* servers'
rows in this table (`federation::remote_key_cache_probe`/
`remote_key_resolver`), so excluding the table entirely would have broken
that feature, but the table also holds this server's own `secret_key`
column — the exact thing this part exists to protect. `load_persistent_rows`
uses a worker-specific 4-column query that never names `secret_key`, and
`provision-federation-worker-role.sql` grants
`SELECT (server_name, key_id, public_key, valid_until_ts)` — PostgreSQL
column-level privileges — so the database itself, not just the C++ query,
refuses `secret_key` to this role.

### Options considered and rejected, for part 2

* **SET ROLE-based database separation instead of a second login.** Already
  rejected above (recorded alongside part 1's own rejected options, since it
  was evaluated at the same time): a session that can `SET ROLE` to a
  restricted role can also `RESET ROLE` back to the login role that granted
  it, so a compromised worker holding the *original* login credential gains
  nothing from a restricted role it can trivially undo.
* **A denylist excluding only the obviously secret-bearing tables, with the
  SQL script granting `SELECT` on `ALL TABLES` (plus `ALTER DEFAULT
  PRIVILEGES` for future tables) and then `REVOKE`ing those few.** This was
  the part-2 design as first implemented, and was rejected on review: both
  halves are fail-*open*. A future migration's new table is automatically
  readable by the worker role (default privileges) and automatically
  hydrated into worker memory (the C++ predicate returns `true` for anything
  not explicitly denied) unless someone remembers to add it to the deny
  side — exactly backwards from a least-privilege boundary, where an
  unrecognised table should be inaccessible until someone deliberately
  grants it. Replaced with the allowlist described above: `GRANT SELECT` is
  per table, no `ALTER DEFAULT PRIVILEGES` and no `GRANT ... ON ALL TABLES`
  appear in the script at all, and the C++ predicate returns `false` for
  anything not in `federation_worker_table_allowlist`.
* **Grant the worker role broad SELECT and rely only on the load profile to
  protect `server_signing_keys`.** Rejected: the load profile is enforced
  entirely in this project's own C++ code, not by PostgreSQL. A future bug
  that constructs `RuntimeStartOptions` without setting
  `database_load_profile` (a new worker code path, a test harness, an
  embedder) would silently fall back to `TableLoadProfile::full` and load
  every table anyway — the database-level column grant on
  `server_signing_keys`, and the plain absence of a `GRANT` for every other
  table, is what makes that failure mode impossible rather than merely
  unlikely. The two mechanisms are deliberately redundant, not substitutes
  for each other, and `tests/unit/test_worker_db_uri.cpp` asserts they name
  the same table set so they cannot drift apart silently.
* **Grant `INSERT`/`UPDATE`/`DELETE` on the allowlisted tables, matching
  `:runtime_role`'s own DML grants.** Rejected: the worker's own
  `PersistentStore` is a read-only snapshot for room-scoped federation
  reads, never the system of record (`src/federation_worker/AGENTS.md` rule
  3) — every write the worker's federation routes need is relayed to main
  over IPC. `provision-federation-worker-role.sql` grants `SELECT` only,
  strictly less than `:runtime_role`. One dormant exception was found on
  review: `state_conflict_resolver` (wired, never overridden by the worker)
  writes `current_state` if a relayed `pdu_sink` response ever carried a
  populated `state_conflict` — which the IPC deserializer never populates
  today, so the path is unreachable in practice. It was deliberately left
  as is rather than "fixed": `current_state` is already allowlisted for
  reads, and a SELECT-only grant makes any future write attempt through
  this path fail closed (a permission error) instead of silently
  succeeding, so the invariant holds even if the unreachability is ever
  broken by accident. See `docs/database-persistence.md`, "Federation
  worker least-privilege role".

### Positive Consequences, part 2

* A PostgreSQL-backed worker compromised through anything short of arbitrary
  filesystem access (part 3's remaining gap) cannot read
  `server_signing_keys.secret_key`, `access_tokens.token_hash`, or any of
  the 44 other non-allowlisted tables via SQL at all — the database itself
  refuses the query, independent of what this project's own code does or
  fails to do.
* The allowlist shape means the security posture of a future migration's
  new table is "worker cannot read it" by default, requiring a deliberate
  two-file change (`federation_worker_table_allowlist` and a `GRANT SELECT`
  line) to widen access — the opposite failure mode from the denylist this
  replaced, where a new table was readable by default.
* The load profile is backend-agnostic and applies even in the
  `allow_shared_database_credentials=true` degraded mode: a worker sharing
  main's login still never pulls unlisted tables into its own process
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
* `load_persistent_rows` now wraps every one of its ~40 per-table `SELECT`
  blocks in a `table_load_profile_includes` check, including the ones that
  are always true for `TableLoadProfile::full` — more boilerplate per block
  than the denylist's seven guarded exceptions, in exchange for the
  fail-closed property above.
* `federation_worker_table_allowlist` (C++) and
  `provision-federation-worker-role.sql`'s per-table `GRANT SELECT` list are
  two separate files that must name the same table set; a unit test
  (`tests/unit/test_worker_db_uri.cpp`, tag `[worker_db_uri]`) parses both
  from the source tree and fails the build if they diverge, so this is
  enforced by CI rather than resting on the cross-references each leaves in
  its own comments.
* SQLite deployments get no role-level improvement from this part — a single
  shared file offers no boundary to separate — and the load profile there
  reduces (but does not eliminate: the file itself remains fully readable by
  the worker process) how much credential material sits resident in worker
  memory. See docs/threat-model.md.

## Decision Outcome, part 3

Chosen option for part 3: **Linux Landlock, applied before the worker
seccomp filter, with a fail-closed unavailable-kernel gate matching
ADR-0041.**

`platform::apply_worker_landlock()`
(`include/merovingian/platform/landlock_hardening.hpp`,
`src/platform/landlock_hardening.cpp`) is called from
`federation_worker::main()` immediately after the config file is parsed and
both inherited fds are validated as open, and immediately before the
existing `apply_worker_hardening()` call that installs the worker seccomp
filter (`src/federation_worker/main.cpp`). It:

1. Queries the running kernel's Landlock ABI version via
   `landlock_create_ruleset(nullptr, 0, LANDLOCK_CREATE_RULESET_VERSION)` —
   the method `landlock(7)` documents for this purpose. A return `< 1` means
   Landlock is unavailable (`ENOSYS` on kernels older than 5.13,
   `EOPNOTSUPP` when Landlock is disabled at boot, e.g. via the `lsm=` boot
   parameter) and is handled by the fail-closed/opt-out gate below.
2. Builds a `handled_access_fs` mask covering every filesystem right this
   project ever restricts (read, write, execute, create, remove, rename-refer,
   truncate), downgraded to whatever bits the reported ABI version actually
   defines (`platform::landlock_handled_access_fs`) — dropping unsupported
   *rights bits* for an older-but-supported kernel is correct Landlock
   practice; refusing to run there is not (see "Options considered and
   rejected" below).
3. Calls `landlock_create_ruleset` with that mask, then one
   `landlock_add_rule` per `platform::LandlockPathRule` in the list
   `platform::build_worker_landlock_rules(config)` builds from the worker's
   own config copy (never a second, drifting hard-coded list) — see
   "Allowlist derivation" below — then `landlock_restrict_self`.
4. Every step past the ABI-availability query is unconditionally fatal on
   failure, independent of `federation.worker.allow_without_landlock`: that
   opt-out means "this kernel has no Landlock", never "Landlock is present
   but broken". A required rule (the SQLite database directory) failing to
   add — including the directory not existing — is fatal; a best-effort
   rule (every OS-integration path) failing to add is logged and skipped,
   since those vary by distribution and their absence degrades a specific
   outbound capability rather than indicating a broken sandbox.

The real `landlock_create_ruleset`/`landlock_add_rule`/`landlock_restrict_self`
calls sit behind an injectable `platform::LandlockHardeningOps` function
table, issued via raw `::syscall()` rather than a libc wrapper (glibc did not
gain wrapper functions for these until 2.38, and the kernel/glibc pair this
project ships against must not be assumed to have them) — the same pattern
`media::DecoderHardeningOps` established, so every fail-closed path is unit
tested (`tests/unit/test_worker_landlock.cpp`, tag `[worker_landlock]`)
without actually restricting the test process. A forked scenario in the same
file applies a real ruleset in a child process (mirroring
`tests/integration/test_seccomp_sqlite_flow.cpp`'s fork pattern, needed
because `landlock_restrict_self` is irreversible for the calling process'
lifetime) and asserts a path outside the allowlist is refused with `EACCES`
while a path inside it still opens — or skips cleanly when the running
kernel has no Landlock support.

### Seccomp ordering

Landlock is applied **before** the worker seccomp filter
(`apply_worker_hardening()`, which still runs immediately afterward in
`main()`), not after. `landlock_create_ruleset`, `landlock_add_rule`, and
`landlock_restrict_self` are Linux syscalls the worker seccomp allowlist
(`k_worker_allowed_syscalls`, `src/platform/seccomp_hardening.cpp`) does not
otherwise need — they run exactly once, at startup, before Landlock
irreversibly denies them anyway (Landlock does not restrict its own syscalls
from being called again, but there is never a reason to call them twice).
Two orderings were available:

* **Apply Landlock first** (chosen): the worker seccomp allowlist never has
  to carry three syscalls that are only ever used once, at startup, and
  never again — keeping that allowlist's contents an accurate description
  of what the worker's *steady-state* runtime needs, which is what a future
  reader auditing it for "why is this syscall allowed" should find.
* **Apply Landlock after seccomp, with the three Landlock syscalls added to
  `k_worker_allowed_syscalls`.** Rejected: this permanently widens the
  worker's post-restriction syscall surface for a capability it only ever
  legitimately uses in the single-digit-millisecond window between exec and
  `landlock_restrict_self`. It also couples the two controls' allowlists
  together for no benefit — Landlock's own fail-closed gate above already
  guarantees the ruleset either applies successfully or the worker never
  reaches the code that would need those syscalls again.

**The worker also inherits the main server's filter.** A seccomp filter
survives `execve`, so when the main server runs with its own seccomp filter
(the production configuration), the worker starts already bound by *main's*
allowlist, before it installs its own. The three Landlock syscalls are
therefore on main's allowlist too (`k_seccomp_filter`,
`src/platform/seccomp_hardening.cpp`); without them the worker's first
`landlock_create_ruleset` killed it under `SECCOMP_RET_KILL_PROCESS`, which
only the full-hardening startup test (`test_server_startup_hardening_flow.cpp`)
caught — the federation-worker integration tests spawn the worker from an
unfiltered test process. Allowing them in main grants nothing: Landlock can
only ever narrow the caller's filesystem access.

### Kernel contract

Two kernel rules the injected-ops unit tests cannot model, each of which
stopped the worker starting until fixed (0.12.13):

* **A rule on a non-directory may carry only file-level rights**
  (`EXECUTE`, `WRITE_FILE`, `READ_FILE`, `TRUNCATE`); requesting `READ_DIR`
  on `/etc/resolv.conf` is `EINVAL`. `real_add_rule` `fstat`s the same
  `O_PATH` fd it passes to the kernel and trims the rights with
  `platform::landlock_access_for_inode`, so there is no gap between checking
  the inode type and adding the rule.
* **`landlock_restrict_self` requires `no_new_privs`** (or
  `CAP_SYS_ADMIN`), otherwise `EPERM`. The worker's seccomp step sets it,
  but later and only when `apply_hardening` is on, so
  `apply_worker_landlock` sets `PR_SET_NO_NEW_PRIVS` immediately before
  `landlock_restrict_self`; a failure there is fatal regardless of the
  opt-out. The worker never execs, so this costs nothing.

The forked real-kernel test skips only when the kernel reports no Landlock
ABI; any other refusal is a failure (it previously skipped on every refusal,
which hid the `EPERM`).

### Allowlist derivation

`platform::build_worker_landlock_rules()` builds two kinds of rules from the
worker's own config copy — see `platform::LandlockPathRule::required`:

* **Config-derived, required.** When `database.backend=sqlite`, the
  *directory* containing `database.sqlite_path` (not just the file) is
  granted `platform::LandlockAccess::read_write`. WAL mode creates `-wal`/
  `-shm` siblings and a rollback journal is created and removed around each
  write transaction — none of which exist on a first boot — so the rule
  must cover directory-level `MAKE_REG`/`REMOVE_FILE`, not just the main
  file. A PostgreSQL-backed worker gets no filesystem rule for the database
  at all: it is reached over the network socket ADR-0062 part 2's separate
  URI authenticates, which Landlock does not restrict (Landlock governs
  filesystem actions only).
* **Fixed, best-effort.** `http::detect_system_ca_trust()`
  (`src/http/outbound_client.cpp`), which the worker's relay pool calls on
  its first outbound federation request, probes eight candidate CA-bundle
  file paths and four candidate CA-bundle directory paths across the
  distributions this project ships on — reading the source directly (rather
  than re-deriving the list independently) is what the rule set's
  certificate-store entries (`/etc/ssl/certs`, `/etc/ssl/cert.pem`,
  `/etc/pki/tls/certs`, `/etc/pki/ca-trust`, `/usr/share/ca-certificates`,
  and related entries, plus the OpenSSL config files) are taken from, plus
  the directories Debian/Ubuntu's per-certificate symlinks under
  `/etc/ssl/certs` commonly resolve into. **Not** the whole of `/etc/ssl` or
  `/etc/pki`: those trees hold the conventional TLS private-key directories
  (`/etc/ssl/private`, `/etc/pki/tls/private`), and a read grant on the
  parent would have exposed any key an operator kept there. Name resolution
  (`getaddrinfo`, used to reach federation peers) reads glibc NSS
  configuration — `/etc/resolv.conf`, `/etc/hosts`, `/etc/nsswitch.conf`,
  `/etc/gai.conf`, `/etc/host.conf` — and lazily `dlopen()`s
  `libnss_dns.so`/`libnss_files.so` from the platform's shared-library
  directories, which are granted `platform::LandlockAccess::read_execute`
  so `mmap(PROT_EXEC)` of the library file succeeds. Timezone data
  (`/usr/share/zoneinfo`, `/etc/localtime`) rounds out the list. These are
  `required = false`: a missing candidate on a given distribution is a
  normal, expected outcome (this project ships on Debian, Fedora, the BSDs,
  and others, each with a different subset present), not a broken sandbox,
  so it is skipped rather than refusing to start.

  Static analysis of `src/http/outbound_client.cpp` and glibc's documented
  NSS/`getaddrinfo` resolution path was the primary source for this list.
  `/proc/self/*` and `/dev/urandom` were considered and excluded:
  `crypto::` and libsodium's own randomness sourcing use `getrandom(2)`
  directly on Linux (no `/dev/urandom` fd, unlike the NetBSD path recorded
  in `docs/adr/` for the fd-sweep fix), and no worker code path reads
  `/proc/self/*`.

### Options considered and rejected, for part 3

* **Best-effort Landlock (log a warning and continue if unavailable),
  instead of fail-closed.** Already rejected above (recorded alongside
  parts 1 and 2's own rejected options, since it was evaluated at the same
  time as this finding): mirrors ADR-0041's rejection of best-effort
  seccomp — an operator who cannot tell "sandboxed" from "silently
  unsandboxed" from the logs will not notice until it matters.
* **Refuse to run on any kernel reporting an ABI version below this
  build's `k_landlock_max_known_abi`**, instead of downgrading the
  requested rights mask to what the reported (possibly lower) ABI
  supports. Rejected: Landlock is explicitly designed for incremental
  adoption — `landlock(7)`'s own guidance is to request the rights the
  running kernel supports, not to require a specific version. A kernel
  reporting ABI 1 (Linux 5.13, no `REFER` or `TRUNCATE` rights) still
  meaningfully restricts the worker to its allowlisted paths for every
  right ABI 1 defines; refusing to start there over two rights this
  project's rule set does not depend on losing would make the fail-closed
  gate needlessly aggressive, the same category of mistake the "any other
  Landlock failure is always fatal" rule above avoids in the other
  direction.
* **A single flat allowlist with no `required`/best-effort distinction** —
  every path either fatal-if-missing or silently-ignored-if-missing.
  Rejected: collapsing the two loses the actual security property each is
  for. The SQLite database directory not existing is a genuine
  misconfiguration the worker should refuse to start under (silently
  ignoring it would mean the worker starts, then fails unrelatedly and
  confusingly the first time it opens the database); a CA-bundle candidate
  from a distribution this worker is not running on is expected and must
  not block startup. `platform::LandlockPathRule::required` names the
  distinction explicitly per rule rather than encoding it as "which list
  this path happens to be in."
* **Grant the worker's own binary and its shared-library dependencies
  `read_execute` individually (resolved via `/proc/self/exe` and `ldd`-style
  introspection at startup)**, instead of the fixed library-directory list.
  Rejected: the worker's own executable and its link-time shared libraries
  are already mapped into the process image before Landlock is applied (ELF
  loading happens at `execve()`, before `main()` runs), so Landlock never
  needs to grant access to them — only libraries loaded *after* the
  restriction point via `dlopen()` (NSS modules, TLS engines) need a rule,
  and those come from a small, well-known set of system library
  directories rather than needing runtime introspection.

### Positive Consequences, part 3

* A federation worker compromised through a memory-safety bug — not merely
  one abusing an intentionally-opened file — can no longer open the
  operator master-key file, either database URI file, or TLS private keys
  directly off disk, closing the residual gap parts 1 and 2 recorded.
  Combined with part 2, a PostgreSQL-backed worker compromised this way has
  no filesystem path to any of this server's cryptographic secrets and no
  database credential beyond its own least-privilege role.
* The `required`/best-effort split means a distribution this project has
  not been explicitly tested on (a CA-bundle path in a different location,
  a non-multiarch library layout) degrades a specific outbound capability
  (TLS verification, name resolution) rather than refusing to start
  entirely — the same fail-open-on-the-unimportant-bits,
  fail-closed-on-the-security-boundary split ADR-0041 already established
  for the seccomp/Landlock unavailability gate itself.

### Negative Consequences, part 3

* The fixed OS-integration path list (`build_worker_landlock_rules`) is a
  static, best-effort approximation of what `getaddrinfo`/libcurl/OpenSSL
  actually open on any given distribution, not a runtime-derived one; a
  distribution whose CA bundle or NSS library lives somewhere entirely
  outside the listed candidates degrades outbound federation (TLS
  verification or name resolution failing) rather than the worker refusing
  to start, which can be a harder failure mode to diagnose than an explicit
  startup refusal. The strace-based derivation above is intended to keep
  this list accurate for the primary distributions this project packages
  for (`packaging/`), not to be exhaustive for every possible host.
* Two independent fail-closed gates (seccomp's `apply_hardening` and
  Landlock's `allow_without_landlock`) now exist for the worker, with
  different scopes and different opt-outs — an operator reading
  `docs/hardening.md` needs to understand both are independent, since
  disabling one does not disable the other (deliberately; see "Seccomp
  ordering" above).
* `federation.worker.allow_without_landlock=true` on a kernel that
  genuinely lacks Landlock leaves the worker exactly as exposed as it was
  before this part shipped — an operator who sets it without reading why
  loses the improvement this part provides, mitigated only by the
  `CRITICAL` log line on every start.

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
* `tests/unit/test_worker_landlock.cpp`, tag `[worker_landlock]` (part 3)
* `CHANGELOG.md`, 0.12.13 (part 3)

### Secret-exposure guard

A rule on a directory grants everything beneath it, so "no secret path is
in the rule set" is not enough: the required read-write grant on the SQLite
database's *directory* would silently expose a master key an operator placed
beside the database. At startup, before applying the ruleset, the worker
checks every rule against `platform::worker_landlock_secret_paths()` (the
master key, both TLS private keys, both database URI files, and the
registration token file) with `platform::find_landlock_rule_covering_secret`,
and refuses to start if any rule equals or is an ancestor of one. Paths are
compared by component after `std::filesystem::weakly_canonical`, matching
how the kernel resolves the rule's path, so a symlink cannot hide an overlap
and `/etc/merov` never covers `/etc/merovingian`. The refusal applies even
with `allow_without_landlock`: it is a secret-placement error, not a kernel
capability question. The shipped layout (secrets in `/etc/merovingian`, the
database in `/var/lib/merovingian`) passes it.
