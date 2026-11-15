# Hardened BSD builds link -pie, and the ELF gate reads elftoolchain readelf

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-14

Technical Story: the FreeBSD release evidence of 1.0.2 reported PIE and BIND_NOW missing from
`build-freebsd-release/src/merovingian-server`.

## Context and Problem Statement

`scripts/collect-release-evidence.sh` runs `scripts/check-elf-hardening.sh` on the server that each platform's release
job builds. On FreeBSD it reported two failures, and they had different causes.

PIE was really missing. `meson.build` added `-pie` to the hardened link flags on Linux only, and left the BSDs to the
packaging scripts: `build-freebsd-pkg.sh` passes `-pie` through `cpp_link_args`. FreeBSD's clang does not link a PIE by
default, so every other hardened FreeBSD build was `ET_EXEC`: `build-bsd.sh --profile hardened`, which the release
evidence job uses, `build.py vm --vm freebsd`, and any build an operator makes from source. Its objects were compiled
with `-fPIE`, and only the link step was missing.

BIND_NOW was not missing. The gate matched GNU binutils' output, `(FLAGS_1) Flags: NOW`. The BSDs' `readelf` is
elftoolchain, which prints DT_FLAGS as `(FLAGS) BIND_NOW` and DT_FLAGS_1 as `(FLAGS_1) NOW`, so a binary linked with
`-Wl,-z,now` failed the check. The old pattern also used `\b`, which POSIX ERE does not define.

## Decision Drivers

* A hardened build must be hardened however it was built, not only when a packaging script built it.
* The gate must give the same answer for the same binary whichever platform's `readelf` reads it.
* The gate must still fail closed: lazy binding must not pass because the pattern is looser.

## Considered Options

* Add `-pie` in `meson.build` for every platform whose hardened build requests RELRO and BIND_NOW (Linux, FreeBSD,
  OpenBSD), and match each `readelf`'s form of the dynamic flags.
* Pass `-pie` from `build-bsd.sh` as the packaging script does, and install GNU binutils on the BSD runners for the gate.

## Decision Outcome

Chosen option: `-pie` in `meson.build`, and a gate that reads both tools, because the build definition is the
one place every build goes through, and the system `readelf` is the one each platform ships.

The pattern accepts a `(BIND_NOW)` entry, `BIND_NOW` as a word in the value of `(FLAGS)`, or `NOW` as a word in the
value of `(FLAGS_1)`. It uses POSIX ERE only. NetBSD stays out of the `-pie` and RELRO/BIND_NOW list, because its
server refuses to start whatever it is linked with (ADR-0378).

### Positive Consequences

* `build-bsd.sh --profile hardened`, `build.py vm --vm freebsd` and the release evidence produce the PIE that the
  shipped `.pkg` already was.
* `tests/tooling/test_check_elf_hardening.py` runs the gate against GNU and elftoolchain output, with a fake `readelf`,
  on every platform the tooling tests run on.

### Negative Consequences

* The FreeBSD `.pkg` build passes `-pie` twice, once from `meson.build` and once from `cpp_link_args`. The linker
  accepts the duplicate.

## Pros and Cons of the Options

### Pass -pie from build-bsd.sh and use GNU readelf

* Bad, because a build from `meson setup -Dhardening=true` alone would still be `ET_EXEC` on FreeBSD.
* Bad, because the gate would depend on a package the BSD hosts do not need for anything else, and would still fail
  wherever only the system `readelf` is installed.

## Links

* Refines the build-time hardening in [docs/hardening.md](../hardening.md#build-time-toolchain-hardening)
* NetBSD's server refuses to start: [ADR-0378](0378-probe-elf-hardening-in-memory-and-keep-netbsd-refused.md)
