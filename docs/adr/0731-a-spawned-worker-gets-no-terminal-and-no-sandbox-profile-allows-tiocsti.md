# A spawned worker gets no terminal, and no sandbox profile allows TIOCSTI or TIOCLINUX

* Status: accepted
* Date: 2026-11-12

Technical Story: run-3 audit of the 1.0.0 release candidate, needs-validation finding NV-1,
`F-sandbox.worker-seccomp.ioctl-denylist-admits-tiocsti-on-inherited-terminal`.

## Context and Problem Statement

The federation worker inherited main's stdin, stdout, stderr and session. When the server is started from a shell, as
the user manual's bootstrap-admin step and the debug-logging guide do, the worker's controlling terminal is that shell's
terminal. The worker seccomp profile kills only the signal-arranging `ioctl` commands (ADR-0642) and allowed the rest,
`TIOCSTI` included. On a kernel that still allows legacy `TIOCSTI` (before Linux 6.2, or with
`dev.tty.legacy_tiocsti=1`), a taken-over worker could queue keystrokes that the operator's shell runs when the server
stops, outside every sandbox. Whether a supported distribution's kernel allows it is outside the repository. How should
the worker be kept away from the terminal, whatever the kernel?

## Decision Drivers

* The fix must hold on any kernel, not only one whose distribution turned legacy `TIOCSTI` off.
* The worker's `ioctl` set was not proved complete by a run (ADR-0642); a wrong allowlist kills the worker in production.
* Logs written to stdout and stderr must keep reaching the operator's terminal or the journal.

## Considered Options

* Two layers: the worker and decoder profiles kill `TIOCSTI` and `TIOCLINUX`, and every spawned worker starts in a
  session of its own with no controlling terminal and `/dev/null` for stdin
* An `ioctl` allowlist for the worker, like the decoder's
* A session of its own only (the kernel refuses `TIOCSTI` on a terminal that is not the caller's controlling terminal)
* Rely on the kernel default

## Decision Outcome

Chosen option: the two layers.

* `argument_check_block` kills `TIOCSTI` and `TIOCLINUX` in the worker profile beside the ADR-0642 commands. The decoder's
  allowlist already refuses both, and a test now says so.
* `WorkerSupervisor::spawn_and_connect` passes `POSIX_SPAWN_SETSID` where the C library has it and opens `/dev/null` on
  the child's stdin as the last file action (after the `adddup2` actions, so a source that sat on fd 0 is moved first).
  `merovingian-fed-worker` calls `setsid()` itself, before anything else that matters, when it is not yet a session
  leader, which covers a C library without the flag; a failure stops the worker. stdout and stderr are kept for logs.
* The thumbnail decoder's forked child calls `setsid()` before `exec`, and exits 127 if it fails. Its stdio was already
  two pipes and `/dev/null`.

Neither layer is enough alone. A session leader without a controlling terminal acquires one when it opens a terminal
without `O_NOCTTY`, so a worker that can open the operator's terminal (no Landlock, `allow_without_landlock=true`) could
make it its controlling terminal again; the seccomp denial still holds then. `TIOCLINUX` acts on a virtual console the
caller has open whether or not it is the controlling terminal. The filter alone would leave the terminal's other state
(job control, hang-up signals) shared for no reason.

### Negative Consequences

* stdout and stderr may still be the operator's terminal, and the worker profile still allows the commands that change
  its settings (`TCSETS`, `TIOCSWINSZ`). Those can garble the terminal or send `SIGWINCH` (ignored by default) to its
  foreground group; they cannot run a command. Closing them needs the full allowlist this ADR rejects.
* The worker no longer receives the terminal's `SIGINT` or `SIGHUP`. Main stops it (`WorkerSupervisor::stop`), and on
  Linux `PR_SET_PDEATHSIG` still ends it if main dies.

## Pros and Cons of the Options

### An ioctl allowlist for the worker

* Good, because a new terminal command would be refused by default.
* Bad, because the worker's set (SQLite, libpq, OpenSSL, the resolver) is not proved by a run; ADR-0642 rejected it for
  that reason and nothing has changed.

### A session of its own only

* Good, because the kernel then refuses `TIOCSTI` on the inherited terminal.
* Bad, because it depends on the worker not reacquiring a controlling terminal, and does nothing for `TIOCLINUX`.

### Rely on the kernel default

* Bad, because Linux before 6.2 (for example the kernels of RHEL 9 and Debian 12) allows it, and the setting is the
  operator's.

## Links

* Refines [ADR-0642](0642-seccomp-refuses-the-fcntl-and-ioctl-commands-that-arrange-signal-delivery.md)
* Related [ADR-0042](0042-spawn-the-federation-worker-with-a-minimal-environment.md)
