# Seccomp refuses the fcntl and ioctl commands that arrange signal delivery

* Status: accepted
* Date: 2026-11-11

Technical Story: release-gate audit run 2, `F-sandbox.decoder-seccomp.fcntl-ioctl-allow-sigio-signal-to-same-uid-processes`.

## Context and Problem Statement

The decoder and federation worker profiles allowed `fcntl` and `ioctl` for every command. A process that holds a pipe can
set a signal owner (`F_SETOWN`, `F_SETOWN_EX`, `F_SETSIG`, `FIOSETOWN`, `SIOCSPGRP`, `TIOCSPGRP`) and turn on `O_ASYNC`
(`F_SETFL`, `FIOASYNC`), and the kernel then signals the owner when the pipe is next ready, as long as the owner has the
same uid. The profiles omit `kill` and `tgkill` to prevent exactly this, so a compromised decoder could still stop or
kill the server. How tight should the argument filter be?

## Decision Drivers

* A filter that is wrong in the permissive direction has already passed its tests once, so each rule needs a real-kernel
  test that a forbidden call is killed and an allowed one is not.
* The decoder does one fixed job. The federation worker links OpenSSL, SQLite, libpq and the resolver.

## Considered Options

* An allowlist of commands for the decoder, and a denylist of exactly the signalling commands for the worker
* An allowlist for both
* A denylist for both

## Decision Outcome

Chosen option: the first. The decoder may use `F_GETFD`, `F_SETFD`, `F_GETFL`, `F_DUPFD_CLOEXEC` and `F_SETFL` without
`O_ASYNC` for `fcntl`, and `TCGETS` and `FIONREAD` for `ioctl`; anything else is killed. The worker is killed on
`F_SETOWN`, `F_SETOWN_EX`, `F_SETSIG`, `F_SETFL` with `O_ASYNC`, `FIOASYNC`, `FIOSETOWN`, `SIOCSPGRP` and `TIOCSPGRP`, and
allows every other command. The command is read from the low word of the argument, as the kernel truncates it to an
unsigned int.

The worker is not on an allowlist because its set (SQLite file locks, `F_SETPIPE_SZ`, socket and terminal ioctls from the
libraries it links, and whatever its dependencies add in a later release) was not proved complete by a run of the
hardened worker over TLS, and an incomplete allowlist kills the federation worker in production. The denylist names every
command that can arrange a signal; a command added to the kernel later that can do the same needs a line here.

### Negative Consequences

* The main server's own profile still allows every command. A compromised main process already holds the server uid and
  the signing key, so this closes nothing it would lose.

## Pros and Cons of the Options

### An allowlist for both

* Good, because a new command is refused by default.
* Bad, because the worker's set was not proved, and a wrong guess is an outage.

### A denylist for both

* Bad, because the decoder needs almost nothing, and a decoder that can use any other command has more reach than it needs.
