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
ADR records the full design; only part 1 has shipped as of this record's
date.

1. **(This ADR, shipped 0.12.13) Secrets arrive over inherited fds, not
   files.** Main derives the IPC auth key once and hands the worker only
   those 32 bytes over a second inherited pipe fd at spawn time. The worker
   never opens the master-key file.
2. **(Planned) A separate, least-privilege worker database login.** A second
   PostgreSQL role (`federation.worker.database.uri_file`), read by main and
   handed to the worker the same way (an inherited fd, not a file the worker
   opens), whose grants exclude `SELECT` on `server_signing_keys`. Until this
   lands, a compromised worker can still read the encrypted `secret_key`
   ciphertext via SQL — it just cannot derive the key that decrypts it, as of
   part 1.
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
the derived key bytes into it, closes its own write end, clears `FD_CLOEXEC`
on only the read end (so it, and only it, survives the upcoming `exec`), and
passes that fd's number as `--ipc-key-fd` alongside the existing `--ipc-fd`.
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
