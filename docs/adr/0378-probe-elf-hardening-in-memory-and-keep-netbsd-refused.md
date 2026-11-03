# Probe ELF hardening in memory, and keep NetBSD refused

* Status: accepted
* Date: 2026-11-03

Technical Story: the first boot of the installed FreeBSD package refused to start with five
hardening checks reporting `unknown`: compiler hardening, linker hardening, PIE, RELRO and seccomp.

## Context and Problem Statement

`is_ready()` blocks startup on anything but `enabled`, and the ELF and seccomp probes returned an
empty result off Linux, so no BSD server has ever been able to start in production. Test runs hid
this: they set `MEROVINGIAN_TEST_DISABLE_HARDENING`, and no CI job booted a BSD package.
`docs/hardening.md` said the refusal had been fixed in 0.12.5, but that fix covered other checks.

The binaries would not have passed a working probe either: only Linux builds asked the linker for
RELRO and BIND_NOW.

## Considered Options

* Probe the running image in memory with `dl_iterate_phdr` on every platform
* Read the executable's file on the BSDs
* Report the ELF checks as "not applicable" off Linux

For NetBSD, which has no equivalent of seccomp, Capsicum or pledge:

* Keep the seccomp check as a startup blocker
* Report seccomp as "not applicable" there too

## Decision Outcome

Chosen options: probe in memory, and keep NetBSD refused.

**The probe reads the image in memory.** It opens no file, so it works after `cap_enter()`, when
the final self-check runs and paths can no longer be opened. OpenBSD also has no way to get the
executable's path. Linux uses the same code, so every Linux test and package boot exercises what
the BSDs run, and a Linux test compares the answer with the file on disk.

**"Not applicable" would be a false claim for the ELF checks.** RELRO, BIND_NOW and PIE exist on
the BSDs. An ELF binary that lacks them is a weaker binary, and the check is there to catch that.
It would also have hidden the missing linker flags.

**seccomp is "not applicable" on FreeBSD and OpenBSD only**, because the control that does that
job there has its own check, which still blocks startup if it was not applied.

**NetBSD stays refused.** Its thumbnail decoder has only rlimits, so decoding untrusted images
would run with the server's whole syscall surface and its read access to the master key and TLS
keys. Audit run 1 rated this reachable only once the BSD startup gate opens, so that gate and the
decoder's confinement have to change together. Do not clear the NetBSD seccomp check without
confining the decoder first. A NetBSD server is refused at startup until then.

### Consequences

* FreeBSD and OpenBSD binaries are linked with `-z relro -z now`. NetBSD's are not, since its
  server cannot start anyway.
* A static Linux build stays covered: `dl_iterate_phdr` works there, and non-PIE reports a zero
  load offset, which the check refuses.
* The OpenBSD and NetBSD packages are still not booted by CI, so this is proven only on FreeBSD
  and Linux.
