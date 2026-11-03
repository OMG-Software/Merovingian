# The thumbnail decoder refuses to run without a platform sandbox

* Status: accepted
* Date: 2026-11-03

Technical Story: security audit run 2, finding F-78: on NetBSD `apply_decoder_hardening()` applied
only `setrlimit` caps and returned `accepted`, so the worker would have decoded untrusted PNG and
JPEG bytes with the whole syscall surface and the server's filesystem reach.

## Context and Problem Statement

Linux (seccomp-bpf), OpenBSD (`pledge`) and FreeBSD (Capsicum) each confine the decoder from inside
the process. NetBSD has no such primitive. The platform ladder in `apply_decoder_hardening()` had no
NetBSD branch, so the function fell through to `accepted = true` after the resource limits. The
worker runs as the server's uid and is forked and exec'd by the parent without a uid change or
chroot, so a libpng or libjpeg-turbo exploit could read the 0400 master key file, the database URI
file and the TLS keys. The worker's own header comment, and `docs/hardening.md`, said otherwise.

Today no NetBSD server gets this far, because it is refused at startup (ADR-0378). That refusal is a
different control, kept for a different reason, and ADR-0378 itself says the startup gate and the
decoder's confinement must change together.

## Considered Options

* **Refuse to decode where no platform sandbox exists (chosen).**
* Keep rlimits only and document the gap. Rejected: rlimits bound memory, CPU and descriptor count;
  they do not stop a compromised decoder from opening files or sockets.
* Drop to an unprivileged uid or chroot in the worker. Rejected for now: the worker would have to
  start with privilege, or the parent would have to be configured with a second user and a
  directory. That is a deployment design and an operator-facing setting, not a one-line fix.
* Report the NetBSD seccomp check as "not applicable" and let the gate open. Rejected: it would open
  the startup gate with the decoder still unconfined.

## Decision Outcome

`apply_decoder_hardening()` returns `accepted = false`, `failed_control = "no platform decoder
sandbox"`, on any platform other than Linux, OpenBSD and FreeBSD. The check is the first thing in
the function, so nothing is applied to the calling process before the refusal. The same refusal sits
in an `#else` of the platform ladder, so a platform that is added later cannot be accepted by
omission. The worker then prints the control and exits `1` before reading stdin, exactly as for any
other failed control, and the media service answers `404` through its existing worker-failure path.

`DecoderHardeningOps::platform_sandbox_available` carries the decision, defaulting to
`decoder_platform_sandbox_available()` (the same preprocessor conditions as the ladder). Tests clear
it to cover the refusal on Linux, where the NetBSD build cannot be run.

There are no thumbnails on NetBSD until privilege separation comes from outside the server process.
Add a NetBSD branch to the ladder only together with that separation, and revisit ADR-0378's startup
gate in the same change.

### Positive Consequences

* A decoder compromise on NetBSD has nothing to decode with; the failure is closed and logged.
* The refusal is testable on Linux.

### Negative Consequences

* NetBSD serves no thumbnails. Clients see `404` for thumbnail requests, as they do when the worker
  is not built.
