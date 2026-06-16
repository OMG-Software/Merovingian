# Immediate Priorities

With the Alpha gates closed, Beta priorities take over. Done so far:
client-server + federation conformance promoted to `spec-covered` (including
state-at-event reconstruction); live PostgreSQL integration tests landed; live
media remote-fetch transport wired; real image thumbnailing via the sandboxed
out-of-process worker landed. The remaining priorities are:

1. Retire one hardening alpha exception per minor release — start with the
   ELF program-header probe (linker hardening / RELRO) and Linux seccomp-bpf
   filter. Update `docs/hardening-alpha-exceptions.md` when an exception lands.
2. ~~Add OpenBSD/NetBSD CI jobs and platform runtime tests.~~ OpenBSD and
   NetBSD added as Tier 1 in CI (build + test suite per PR via `vmactions/*-vm`)
   in 0.8.12/0.8.13; platform runtime tests run on each; support tiers
   documented in `docs/platform-support.md`.
3. Promote CI from build/test checks to full capability gates with conformance,
   fuzzing (already gated), platform, packaging, and signed release evidence.
