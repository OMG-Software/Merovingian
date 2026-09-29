# Merovingian Security Audit Report — 29 September 2026

**Scope:** Full security audit across all high-risk surfaces, audited sequentially one
area at a time.
**Baseline:** `6a04242` (0.12.13).
**Method:** For each area, one specialist auditor subagent, then one independent
adversarial verifier subagent whose job was to refute each finding, then orchestrator
spot-checks of every finding rated high or critical. Only findings that survived
verification are listed as findings; refuted ones are recorded at the end of each area.
**Authority:** Matrix spec v1.19 (`docs/matrix-v1.19-spec/`), project `AGENTS.md` files,
`docs/security-coding-rules.md`, `docs/threat-model.md`.
**Relationship to the earlier report:** `docs/security-audit-report-2026-09.md`
(33 findings, fixed in 0.12.9). Each area below re-checks the relevant earlier fixes for
regressions before looking for new defects.

This report records findings only. No production code was changed by this audit. Every
finding has a GIVEN/WHEN/THEN acceptance criterion; per `AGENTS.md`, the fix for each
must start with that test.

## Attacker models

| ID | Attacker |
|----|----------|
| A1 | Unauthenticated remote client |
| A2 | Authenticated local user (non-admin) |
| A3 | Malicious remote federating homeserver |
| A4 | Malicious or compromised application service |
| A5 | Compromised federation worker or thumbnail worker (escape towards the main process) |
| A6 | Local unprivileged OS user on the host |
| A7 | Malicious identity server, push gateway or remote media server answering our requests |

## Severity guide

- **Critical:** remote auth bypass, RCE, memory corruption reachable by A1/A3, signing-key leak.
- **High:** spec MUST violation or access-control bypass with real impact, cheap remote
  DoS, secret leakage, integrity defect reachable in production.
- **Medium:** real defect that is partly mitigated or needs unusual preconditions.
- **Low:** defence in depth.

## Areas

| # | Area | Status |
|---|------|--------|
| 1 | Authentication, sessions, application-service authentication | pending |
| 2 | Client-Server authorisation and room access control | pending |
| 3 | HTTP transport, TLS and request-level DoS | pending |
| 4 | Federation inbound (X-Matrix, PDU ingestion, keys, backfill, membership) | pending |
| 5 | Event engine (auth rules, state resolution, redaction, canonical JSON) | pending |
| 6 | Outbound requests and SSRF (discovery, push, identity, appservice, remote media) | pending |
| 7 | Cryptography, key management and worker IPC | pending |
| 8 | Process isolation and platform hardening (workers, seccomp, sandboxes) | pending |
| 9 | Media repository and thumbnailer | pending |
| 10 | Database, persistence and migrations | pending |
| 11 | Configuration, observability, logging and packaging | pending |

