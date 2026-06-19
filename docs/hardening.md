# Runtime hardening

This document describes the hardening defences Merovingian applies at build
_time_, at startup, and while serving traffic. It covers defences that are
cross_platform_ and defences that are _platform_specific_ (Linux, FreeBSD,
NetBSD, OpenBSD, and the portable/service_manager profile).

For open hardening work and production-gating status, see
[`todos/capability-gaps.md`](todos/capability-gaps.md).

## Cross_platform defences

These defences are present on every supported platform, either inside the
binary or in the service_manager configuration that ships with the packages.

### Build_time toolchain hardening

`meson.build` adds the following compile_and_link hardening whenever
`-Dhardening=true` is set (the default for packages):

| Defence | Where it lives | Notes |
| --- | --- | --- |
| Stack protector | `hardening_compile_flags` (`-fstack-protector-strong`) | Compiler inserts stack canaries. |
| Stack clash protection | `hardening_compile_flags` (`-fstack-clash-protection`) | Guards against stack clash attacks. |
| Control_flow protection | `hardening_compile_flags` (`-fcf-protection=full`) | CET/IBT on x86_64. |
| FORTIFY_SOURCE | `hardening_compile_flags` (`-D_FORTIFY_SOURCE=3`) when `optimization != '0'` | Checked libc wrappers. |
| Hidden visibility | `hardening_compile_flags` (`-fvisibility=hidden`) | Limits ELF symbol exposure. |
| Trivial auto_var init | `hardening_compile_flags` (`-ftrivial-auto-var-init=zero`) | Uninitialised locals are zeroed. |
| Position_independent executable | `hardening_compile_flags` (`-fPIE`) and link args (`-pie`) | Enables ASLR. |
| No_exec stack | `hardening_link_flags` (`-Wl,-z,noexecstack`) | ELF GNU_STACK note is non_executable. |
| RELRO + BIND_NOW | `hardening_link_flags` (`-Wl,-z,relro -Wl,-z,now`) on GNU/Linux | Full RELRO; dynamic relocations resolved at load time. |
| Static PIE fallback | `scripts/build-static-linux.sh` (`-static-pie`) | Fully static, position_independent musl build for Linux. |

The startup hardening self_check probes the same flags at runtime:

* `compiler hardening` checks for `__SSP__`/`__SSP_STRONG__`/`__SSP_ALL__`,
  `_FORTIFY_SOURCE > 0`, and `__PIE__`/`__pie__`.
* `linker hardening`, `PIE`, and `RELRO` parse `/proc/self/exe` on Linux to
  confirm `PT_GNU_RELRO`, `DT_BIND_NOW`, and `PT_GNU_STACK` without `PF_X`.
  Static or non_ELF builds report `unknown` rather than `disabled`.

### C++ memory and type safety

The project uses C++26 with strict rules that reduce memory_safety bugs:

* RAII everywhere; no raw `new`/`delete`, `malloc`/`free`.
* Smart pointers for dynamic ownership; references preferred over pointers.
* `core::FileDescriptor` is a move_only RAII wrapper that closes its fd on
  destruction and provides `set_cloexec()`.
* `core::SecretBuffer` holds signing-key material mlocked via `sodium_mlock`
  on construction and wiped on destruction with `sodium_munlock` (which
  zeroises and unpins and is an optimisation barrier the compiler cannot
  elide, unlike the prior `std::ranges::fill` dead store). Custom move-ctor
  and move-assign transfer the mlock to the destination and wipe the source,
  so the secret is never duplicated and never left pinned in a moved-from
  object. It is move_only and non_copyable. `src/core` links libsodium.

### Cryptographic boundary

All cryptography is delegated to libsodium. The project does not implement its
own primitives.

* `sodium_init()` is wrapped in per_module `static` `sodium_is_ready()` helpers
  so it is called once and failures are checked (`src/events/event_signer.cpp`,
  `src/homeserver/auth_service.cpp`, `src/crypto/secret_box.cpp`, etc.).
* Passwords and the registration token are hashed with Argon2id
  (`crypto_pwhash_str` / `crypto_pwhash_str_verify`).
* Access_token HMAC and signing_secret encryption keys are derived from the
  operator's master key with domain_separated libsodium generic hashes
  (`crypto_generichash`).
* The Ed25519 server signing secret is stored encrypted at rest via
  `crypto::secret_box_encrypt` (XSalsa20-Poly1305 with a random nonce).
* Constant_time comparison for fixed_size values uses `sodium_memcmp`. Variable
  length secrets are compared by hashing both inputs with a domain_separated
  `crypto_generichash` context and then comparing the fixed_size digests with
  `sodium_memcmp`, so the comparison does not leak the secret length.
* Short_lived plaintext secrets are pinned while in use with `sodium_mlock` /
  `sodium_munlock` and overwritten with zeros before release
  (`src/homeserver/auth_service.cpp` registration_token handling).
* The seccomp_bpf allowlist permits `mlock`, `munlock`, `mlockall`,
  `munlockall`, and `getrandom` so libsodium can lock pages and fetch entropy.

### Configuration and secret file permissions

Before loading configuration or secret files, the bootstrap path validates
POSIX metadata:

* `src/platform/file_metadata.cpp` reads file kind and mode with `lstat`.
* Configuration and TLS certificate files must be regular files without group
  or other write or any execute bit (`is_secure_config_file`).
* Secret files (master key, TLS private key, registration token) must be
  regular owner_read_only, non_executable files with no group/other access
  (`is_secure_secret_file`).
* These checks run in `src/main.cpp` before any listener is created.

### Signal handling and graceful shutdown

`src/net/shutdown_signal.cpp` installs a self_pipe and SIGINT/SIGTERM handlers.
The handler does only signal_safe work: it writes one byte to the pipe and sets
an atomic flag. The main thread unblocks `poll()` and initiates clean shutdown.
`SIGPIPE` is ignored so a worker that dies mid_request cannot terminate the
parent.

### Out_of_process thumbnail worker sandbox

The main server **never** decodes untrusted image bytes in_process. It spawns
`merovingian-thumbnail-worker` via `fork()`/`execv()` (`src/media/thumbnailer.cpp`
and `src/media/thumbnail_worker_main.cpp`):

* Parent and child communicate through `O_CLOEXEC` pipes (`pipe2()` on Linux,
  `pipe()` + `fcntl(F_SETFD, FD_CLOEXEC)` elsewhere).
* The child `dup2()`s the pipe ends onto stdio, then calls
  `core::close_all_file_descriptors_except()` with a `std::span<int const>` to
  close every inherited fd other than stdio. The span overload is allocation-free
  and async-signal-safe so it can run immediately after `fork()` in a
  multi-threaded parent. The sweep:
  * uses `/proc/self/fd` on Linux;
  * skips `/dev/fd` directory walks on FreeBSD, NetBSD, and OpenBSD (those
    directories contain an entry for every *possible* fd, not only open ones);
  * falls back to a capped `fcntl(F_GETFD)` scan of at most 1024 descriptors.
* Before `execv()` the child sets `prctl(PR_SET_NO_NEW_PRIVS, 1, ...)` on Linux
  so a compromised worker cannot escalate through setuid/setcap helpers.
* Inside the worker, `harden()` clamps resources:
  * `RLIMIT_CPU` = 15 s in production release builds, 60 s in non-release builds, 120 s under sanitizers (ASan/UBSan/TSan are slow on CI QEMU);
  * `RLIMIT_FSIZE` = 64 MiB;
  * `RLIMIT_CORE` = 0;
  * `RLIMIT_NOFILE` = 16;
  * `RLIMIT_AS` = 768 MiB in production builds (skipped under sanitizers);
  * seccomp_bpf is installed in production builds (skipped under sanitizers).
* The worker rejects images whose width or height exceeds 4096 and whose pixel
  count exceeds the request's `max_pixels`.

## Platform_specific defences

### Linux

Linux receives the richest set of in_process controls.

| Defence | Implementation | Notes |
| --- | --- | --- |
| seccomp_bpf syscall allowlist | `src/platform/seccomp_hardening.cpp` | Installed in `main.cpp` before listeners bind and inside the thumbnail worker. |
| Architecture guard | `src/platform/seccomp_hardening.cpp` | Filter starts with an `AUDIT_ARCH_X86_64` or `AUDIT_ARCH_AARCH64` guard and fails closed on unsupported architectures. |
| Fail_closed default | `src/platform/seccomp_hardening.cpp` | Unlisted syscalls return `SECCOMP_RET_KILL_PROCESS`. |
| No new privileges | `prctl(PR_SET_NO_NEW_PRIVS, 1, ...)` | Applied by `apply_seccomp_filter()` and `apply_runtime_hardening_controls()`. |
| Capability bounding set drop | `apply_linux_capability_bounding_set()` | Calls `prctl(PR_CAPBSET_DROP, cap, ...)` for every capability. |
| Core dump policy | `apply_linux_core_dump_policy()` | `setrlimit(RLIMIT_CORE, {0, 0})` and `prctl(PR_SET_DUMPABLE, 0)`. |
| Self_check probes | `src/platform/hardening_self_check.cpp` | Confirms `Seccomp: 2`, `PR_GET_NO_NEW_PRIVS`, and `RLIMIT_CORE == 0`. |
| systemd sandboxing | `packaging/systemd/merovingian.service` | `PrivateTmp=true`, `ProtectSystem=strict`, `ProtectHome=true`, `NoNewPrivileges=true`, `CapabilityBoundingSet=`, `SystemCallArchitectures=native`, `MemoryDenyWriteExecute=true`, etc. |

The seccomp_bpf filter is deliberately narrow: it allows only the syscalls the
runtime actually needs. The filter is installed in `main.cpp` before
`start_client_server` is called, so the database layer (SQLite) runs under the
filter from its first access onwards.

**Filesystem syscalls in the allowlist** — the filter permits the following
filesystem-mutating calls because SQLite requires them for correct operation:

| Syscall | Reason |
| --- | --- |
| `ftruncate` | WAL file truncation during checkpoints and journal rollback. |
| `unlink`, `unlinkat` | Journal file deletion on commit in DELETE journal mode. |
| `rename`, `renameat`, `renameat2` | Atomic commit in some SQLite configurations; `std::filesystem::rename`. |
| `fstatfs`, `statfs` | Device sector-size probe during WAL-mode open. |
| `fallocate` | `posix_fallocate(3)` path: SQLite pre-allocates database and WAL file space; glibc maps this to `fallocate(2)` on filesystems that support it. |

The path-based `truncate` and permission-mutation calls (`chmod`, `fchmod`,
`fchmodat`, `umask`, `mkdir`) remain blocked. The service-manager sandbox
(`ProtectSystem=strict`, writable paths limited to `/var/lib/merovingian` and
`/run/merovingian`) bounds what `unlink`/`rename`/`ftruncate`/`fallocate` can
actually reach.

**glibc per-CPU and synchronisation syscalls** — allowed because modern glibc
(2.35+) calls these from `malloc`, thread initialisation, and after `fork()`:

| Syscall | Reason |
| --- | --- |
| `rseq` | glibc 2.35+ registers a per-thread restartable-sequence area after `fork()`. glibc 2.36+ also uses `rseq` inside the `malloc` per-CPU cache. |
| `membarrier` | glibc 2.31+ issues `MEMBARRIER_CMD_PRIVATE_EXPEDITED` from the `malloc` fast path on multi-processor systems. |
| `getcpu` | Returns the running CPU/NUMA node; used by glibc's per-CPU TLS and `malloc` implementation. |

### FreeBSD / NetBSD / OpenBSD (BSD)

Merovingian builds and runs on all three BSDs, but some kernel sandbox APIs are
still alpha exceptions:

* `pledge` / `unveil` (OpenBSD), `cap_enter()` (FreeBSD Capsicum), `jail`, and
  `chroot` are documented in the BSD hardening plan but are **not yet invoked**
  inside the process. They are tracked as `alpha_exception` in the startup
  self_check.
* The portable `setrlimit` gates are validated by the BSD hardening profile, and
  the thumbnail worker applies `RLIMIT_CPU`, `RLIMIT_FSIZE`, `RLIMIT_CORE`,
  `RLIMIT_NOFILE`, and `RLIMIT_AS`.
* The thumbnail worker fd sweep uses the capped `fcntl(F_GETFD)` fallback on
  every BSD instead of walking `/dev/fd`.
* Service_manager scripts apply the privilege drop and filesystem restrictions
  that the in_process code defers during alpha:
  * OpenRC: `packaging/openrc/merovingian` (`command_user=merovingian:merovingian`,
    `directory=/var/lib/merovingian`).
  * FreeBSD/NetBSD/OpenBSD rc.d: `packaging/rc.d/merovingian` and
    `packaging/openbsd/rc.d/merovingian` (`merovingian_user`, runtime and state
    directories owned by the service user).

### Portable / other Unix

On platforms that are neither Linux nor a recognised BSD, Merovingian uses the
`portable` hardening profile (`default_portable_hardening_profile()`). The
profile:

* requires that the hardening plan documents privilege drop, filesystem
  restrictions, resource limits, memory locking, random source, and signal
  handling;
* applies **no** kernel_specific syscalls itself;
* relies on the service manager to drop privileges and confine the filesystem.

## Startup hardening self_check

`src/platform/hardening_self_check.cpp` runs in `src/main.cpp` just before the
server binds listeners. Each check reports one of:

* `enabled` — the defence is active;
* `disabled` — the defence was explicitly turned off (hard failure);
* `unknown` — the probe could not confirm the defence (e.g. static binary,
  unsupported kernel);
* `alpha_exception` — a documented alpha_only carve_out.

`run_server()` refuses to bind listeners if any check reports `disabled`.
`is_production_ready()` returns true only when every check is `enabled`, so
production release gating catches any remaining `alpha_exception`.

## Packaging and deployment hardening

The packaging scripts request the same linker hardening that `meson.build`
advertises:

* `scripts/build-deb.sh` and `scripts/build-rpm.sh` pass
  `-pie -Wl,-z,relro -Wl,-z,now`.
* `scripts/build-static-linux.sh` passes `-static-pie -Wl,-z,relro -Wl,-z,now` and
  verifies the resulting binary has no dynamic interpreter.
* The RPM specs (`packaging/rpm/merovingian.spec`,
  `packaging/rhel/merovingian.spec`, `packaging/opensuse/merovingian.spec`)
  pass the same flags and strip conflicting `_FORTIFY_SOURCE` definitions from
  the distribution's `%optflags`.

## CI gates

Hardening is exercised by automated tests:

* `tests/unit/test_seccomp_hardening.cpp` asserts the fail_closed default action,
  the architecture guard, that SQLite journal syscalls are allowed, and that
  privilege-mutation syscalls (chmod, fchmod, fchmodat, umask, mkdir, truncate) remain denied.
* `tests/unit/test_file_descriptor.cpp` exercises `FileDescriptor::set_cloexec()`
  and `close_all_file_descriptors_except()`.
* `tests/unit/test_media_thumbnailer.cpp` covers the CLOEXEC pipe path and the
  sandboxed worker round_trip.
* `tests/unit/test_runtime_hardening.cpp` validates profile accept/reject logic.

## What is intentionally deferred

The following controls are documented `alpha_exception` placeholders:

* OpenBSD `pledge`/`unveil`.
* FreeBSD `cap_enter()` (Capsicum).
* In_process privilege drop (`setresgid`/`setresuid`).
* In_process filesystem confinement (Landlock / `unveil` / Capsicum).

They are delegated to the supplied service-manager units. The
production readiness gate will not pass until each is retired. See
[`todos/capability-gaps.md`](todos/capability-gaps.md) for open hardening items.
