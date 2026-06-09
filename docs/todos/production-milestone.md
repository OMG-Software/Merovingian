# Production v1.0.0 — Open Items

Production means all security, correctness, conformance, platform, packaging,
and release evidence is closed for a signed release artifact. Packages must not
be published as production releases while any blocking gate remains open.

- Keep real listener coverage in CI and prove the server serves requests until
  stopped by the service manager.
- Require configured TLS with validated certificate and private-key files for
  public listeners; keep loopback cleartext available for reverse-proxy
  deployments.
- Complete full Matrix v1.18 conformance, persistence, endpoint coverage, and
  production-grade rate limiting for client-server routes.
- Store access tokens only as versioned cryptographic hashes generated from
  LibSodium CSPRNG output.
- Store passwords only with LibSodium Argon2id password hashes.
- Enforce PostgreSQL transaction coverage, migration coverage, and role grants
  against real temporary databases.
- Fail closed when required production hardening controls are unavailable.
- Pass conformance, fuzz, sanitizer, static-analysis, platform, packaging, and
  release-readiness checks before creating a release tag.
- Add signed release artifacts, reproducible builds, dependency pinning policy,
  license review, provenance, and artifact signatures.
- Record compiler version, linker flags, dependency versions, test logs,
  sanitizer logs, fuzz target names, package checksums, and artifact signatures
  in release notes.
