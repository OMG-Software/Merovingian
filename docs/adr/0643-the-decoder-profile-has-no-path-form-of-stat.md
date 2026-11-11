# The decoder profile has no path form of stat

* Status: accepted
* Date: 2026-11-11

Technical Story: release-gate audit run 2, `F-filesystem-process.decoder-seccomp.path-based-stat-allowed`.

Corrects [ADR-0053](0053-the-thumbnail-decoder-gets-its-own-syscall-profile.md), which said every path-based filesystem
call is denied for the decoder while `newfstatat` and `statx` were on its allowlist.

## Context and Problem Statement

glibc implements `fstat` as `newfstatat(fd, "", buf, AT_EMPTY_PATH)`, so the decoder profile allowed `newfstatat` and
`statx` outright. Both take a path, so a compromised decoder could read the type, size, mode, owner and times of any
path the server's uid can reach. The audit proposed restricting them to `AT_EMPTY_PATH` on a descriptor.

## Decision Outcome

Chosen option: remove both from the decoder allowlist and keep `fstat`. A seccomp program cannot read the path string,
and an absolute path is resolved whatever descriptor and flags are passed, so no argument filter makes the path forms
safe: a filter that required `AT_EMPTY_PATH` and a descriptor below 3 would still admit `newfstatat(0, "/etc/shadow", ..,
AT_EMPTY_PATH)`. The decoder reads and writes its pipes with `read` and `write` and never calls `fstat` itself, which a
run of the hardened worker under this filter confirms (the `[thumbnail]` integration tests).

### Negative Consequences

* A libc that routes a C library call the decoder makes through `newfstatat` would kill the decoder at that call. The
  worker avoids stdio and iostreams for this reason (`docs/hardening.md`), and the integration test would fail on such a
  libc.

## Links

* Corrects [ADR-0053](0053-the-thumbnail-decoder-gets-its-own-syscall-profile.md)
