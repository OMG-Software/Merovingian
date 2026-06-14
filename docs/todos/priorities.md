# Immediate Priorities

With the Alpha gates closed, Beta priorities take over. Done so far:
client-server + federation conformance promoted to `spec-covered` (including
state-at-event reconstruction); live PostgreSQL integration tests landed; live
media remote-fetch transport wired; real image thumbnailing via the sandboxed
out-of-process worker landed. The remaining priorities are:

1. Retire one hardening alpha exception per minor release — start with the
   ELF program-header probe (linker hardening / RELRO) and Linux seccomp-bpf
   filter. Update `docs/hardening-alpha-exceptions.md` when an exception lands.
2. Add policy server transport integration and richer moderation workflows
   (durable policy-rule persistence already exists).
3. Define the observability scrape/export, log-format, and trace-correlation
   contracts plus operator docs.
4. Add OpenBSD/NetBSD CI jobs and platform runtime tests.
5. Promote CI from build/test checks to full capability gates with conformance,
   fuzzing (already gated), platform, packaging, and signed release evidence.
