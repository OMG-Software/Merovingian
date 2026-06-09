# Immediate Priorities

With the Alpha gates closed, Beta priorities take over:

1. Complete Matrix v1.18 conformance for client-server endpoints currently
   marked `partial` — promote them to `covered` with conformance fixtures.
2. Add Matrix federation conformance fixtures covering join, leave, invite,
   backfill, and key-rotation scenarios end to end.
3. Retire one hardening alpha exception per minor release — start with the
   ELF program-header probe (linker hardening / RELRO) and Linux seccomp-bpf
   filter. Update `docs/hardening-alpha-exceptions.md` when an exception lands.
4. Wire live remote media transport/server-discovery into the new remote-ingest
   boundary and replace thumbnail metadata with real resampling output.
5. Promote CI from build/test checks to full capability gates with conformance,
   fuzzing (already gated), platform, packaging, and signed release evidence.
