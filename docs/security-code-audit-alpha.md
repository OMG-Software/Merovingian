# Alpha security code audit

Date: 2026-05-18
Branch: `codex/security-audit`

## Executive summary

This audit reviewed the alpha codebase, packaging, and GitHub Actions workflows
for security-critical implementation gaps. The highest-risk issues are in the
registration and listener-routing paths:

- 1 critical finding
- 1 high finding
- 2 medium findings

The most serious defect is that runtime registration does not enforce the
configured registration-token policy, while the first successful registration is
automatically granted admin privileges. A fresh deployment with registration
enabled can therefore be claimed by the first unauthenticated caller.

## Scope

In scope:

- Repository: `Merovingian`
- Reviewed branch: `codex/security-audit`
- Deployment targets:
  - `merovingian-server` POSIX server runtime
  - `merovingian-db-migrate` CLI tool
  - systemd, OpenRC, and BSD rc.d packaging assets
  - GitHub Actions CI, release, fuzz, and PostgreSQL workflows
- Security-critical code paths:
  - registration, login, logout, session lookup, admin checks
  - federation request verification, remote-key discovery, outbound HTTPS
  - admin routes, trust-and-safety routes, media moderation routes
  - configuration validation, secret-file validation, runtime hardening checks
  - release publishing and artifact handling

Out of scope:

- Reverse proxies, DNS, `.well-known`, TLS certificates, and deployment-specific
  firewall rules for a live environment
- Production secrets, backups, and operational logs from a real deployment
- Third-party hosted infrastructure outside repository-owned code and workflows

Assumptions:

- Findings are based on repository code and workflow behavior, not a live
  staging or production system.
- The audit treats documented alpha exceptions as accepted risk unless the code
  surface expands exposure beyond what the documentation claims.

## Threat model

Primary attackers considered:

- Anonymous internet user reaching client or federation listeners
- Authenticated non-admin Matrix user
- Malicious federated homeserver
- Operator error during alpha release publication
- Compromised or tampered CI/release artifact consumer path

Trust boundaries reviewed:

- HTTP client listener to Matrix client-server adapter
- Federation listener to legacy local router
- Local runtime to persistent SQLite/PostgreSQL state
- Outbound federation discovery to pinned-address HTTPS client
- GitHub Actions build outputs to published prerelease assets

Sensitive assets reviewed:

- Access tokens and password hashes
- Server signing-key material and remote-key cache
- Admin-only routes and moderation surfaces
- Release artifacts and checksums

## Method

Manual review:

- `src/homeserver/*`
- `src/federation/*`
- `src/http/*`
- `src/platform/*`
- `src/database/*`
- `packaging/*`
- `.github/workflows/*`
- `docs/*` claims that define intended security controls

Automated scanning:

- Local availability check:
  - `where.exe semgrep` -> not installed
  - `where.exe gitleaks` -> not installed
  - `where.exe trivy` -> not installed
- Repository-native automated coverage found:
  - CodeQL workflow
  - static-analysis workflow
  - sanitizer workflow
  - fuzz workflow
  - secret scanning workflow
  - dependency vulnerability triage workflow
  - SBOM generation workflow
- Repository-native automated coverage not found:
  - IaC/container scanning workflow

Scanner absence is treated as a test gap unless it directly leaves a published
surface unverifiable.

## Findings

### Critical: registration-token policy is not enforced and first registration becomes admin

- Severity: Critical
- Status: Fixed in 0.1.65
- Affected code:
  - [src/homeserver/client_server.cpp](/C:/dev/Merovingian/src/homeserver/client_server.cpp:1427)
  - [src/homeserver/auth_service.cpp](/C:/dev/Merovingian/src/homeserver/auth_service.cpp:172)
  - [src/config/config.cpp](/C:/dev/Merovingian/src/config/config.cpp:379)
  - [docs/security-review-checklist.md](/C:/dev/Merovingian/docs/security-review-checklist.md:11)
- Exploitability: High on any fresh deployment with registration enabled
- Impact: Unauthenticated admin takeover

Evidence:

- The Matrix register handler accepts only `username` and `password` and passes
  them straight into `register_local_user`, with no registration-token field
  parsed or validated.
- `register_local_user` evaluates only `registration.enabled`; it hardcodes the
  local-policy block flag to `false` and never consults
  `security.registration.require_token`.
- The first successful registration is marked admin via
  `first_user_is_admin = runtime.database.users.empty()`.
- This contradicts the repository's own security checklist, which says admin
  bootstrap must be explicit and not claimable through public registration.

Risk:

- An operator can believe registration is token-gated because config validation
  enforces `require_token=true` when registration is enabled.
- In practice, the runtime path does not honor that contract, so the first
  external caller can become the server admin.

Recommended fix:

- Enforce registration-token validation in the real registration path before any
  user is created.
- Remove implicit first-user admin assignment from public registration.
- Introduce a separate operator bootstrap mechanism with explicit one-time
  controls and dedicated tests.

Retest:

- Added a BDD regression that starts a token-protected client-server runtime,
  verifies missing and incorrect registration tokens are rejected, verifies the
  configured token is accepted, and asserts the created account is not admin.
- The runtime now requires `security.registration.token_file` when token-gated
  registration is enabled, parses Matrix UI-auth registration tokens from the
  JSON request body, compares them with LibSodium constant-time comparison, and
  moves admin creation behind the explicit `bootstrap_admin_user` API.
- `merovingian-server` now exposes an explicit operator startup path,
  `--bootstrap-admin <localpart> --bootstrap-admin-password-file <path>`, which
  creates the admin account through `bootstrap_admin_user` before listener bind.

### High: federation listener is routed through the legacy local router and exposes non-federation surfaces

- Severity: High
- Status: Fixed in 0.1.65
- Affected code:
  - [src/main.cpp](/C:/dev/Merovingian/src/main.cpp:555)
  - [src/net/listener.cpp](/C:/dev/Merovingian/src/net/listener.cpp:38)
  - [src/homeserver/local_http_router.cpp](/C:/dev/Merovingian/src/homeserver/local_http_router.cpp:215)
  - [docs/todos/capability-gaps.md](/C:/dev/Merovingian/docs/todos/capability-gaps.md)
- Exploitability: High whenever the federation listener is internet-reachable
- Impact: Unnecessary attack-surface expansion on the federation port

Evidence:

- The listener dispatcher sends every non-client listener to
  `HttpDispatchMode::local_router`.
- The federation listener is created whenever federation is enabled.
- The local router serves:
  - `/_merovingian/admin/health`
  - `/_merovingian/admin/metrics`
  - `/_merovingian/admin/audit`
  - admin media moderation routes
  - legacy register/login compatibility routes
  - federation routes

Risk:

- The federation port is supposed to expose federation surfaces, but instead it
  also exposes admin and client compatibility routes.
- The admin routes are token-gated, but they are still unnecessarily reachable
  on the public federation socket and therefore enlarge the brute-force and
  bug-discovery surface.
- The legacy pipe-delimited register/login handlers remain reachable on the same
  listener, which weakens boundary separation.

Recommended fix:

- Split the federation listener onto a federation-only router.
- Move admin operations to a loopback-only or Unix-socket-only surface.
- Remove legacy client compatibility endpoints from the federation dispatch

Retest:

- Added a BDD regression that dispatches admin, client registration, and
  `GET /_matrix/key/v2/server` requests through `HttpDispatchMode::federation`.
  Admin and client routes return `404`, while the federation key endpoint
  remains available.
- Production listener startup now maps client listeners to the Matrix
  client-server adapter and federation listeners to a federation-only router,
  leaving the legacy local router for internal compatibility paths only.
  path.

### Medium: unauthenticated rate limiting is global per route and allows easy cross-user denial of service

- Severity: Medium
- Affected code:
  - [src/homeserver/client_server.cpp](/C:/dev/Merovingian/src/homeserver/client_server.cpp:443)
- Exploitability: Moderate
- Impact: Login and registration availability loss for unrelated users

Evidence:

- Rate-limit bucket keys are prefixed with the access token.
- The code comment explicitly states that unauthenticated routes such as login
  and register carry an empty token and therefore share a global bucket per
  route.
- The same comment notes that remote-IP scoping is still a follow-up item.

Risk:

- One source can consume the shared unauthenticated budget and cause `429`
  responses for other users attempting login or registration.
- This is both an availability problem and a weak brute-force containment model,
  because all anonymous callers are collapsed into the same quota bucket.

Recommended fix:

- Add remote address tracking to `LocalHttpRequest`.
- Bucket unauthenticated auth endpoints by source IP or a stronger abuse key.
- Keep stricter per-account and per-device limits on authenticated paths.

### Medium: alpha release assets remain unsigned and lack provenance attestations

- Severity: Medium
- Affected code:
  - [docs/security-review-checklist.md](/C:/dev/Merovingian/docs/security-review-checklist.md:44)
  - [docs/todos/production-milestone.md](/C:/dev/Merovingian/docs/todos/production-milestone.md)
  - [docs/release-process.md](/C:/dev/Merovingian/docs/release-process.md:45)
  - [\.github/workflows/release.yml](/C:/dev/Merovingian/.github/workflows/release.yml:173)
- Exploitability: Moderate
- Impact: Consumers cannot strongly verify artifact origin or build integrity

Evidence:

- The release workflow publishes tarballs and SHA-256 checksum files only.
- The repository now has dedicated secret-scanning, dependency-triage, and SBOM
  workflows, and published releases can carry SBOM assets.
- Release artifacts and checksum manifests are still not signed.
- No provenance or build attestation workflow exists for release assets.

Risk:

- Public prerelease consumers have no signed provenance chain for downloaded
  assets.
- Checksums without signatures prove transfer integrity only if the GitHub
  release page is already trusted.

Recommended fix:

- Sign release artifacts and checksum manifests.
- Add provenance/attestation generation for release builds.

## Test gaps

- No local Semgrep, Gitleaks, or Trivy tooling was installed in this workspace.
- Token-protected public registration and federation-only dispatch now have BDD
  regressions, but the full socket-level federation listener path still needs a
  network integration test.
- No test covers remote-IP-scoped anonymous rate limiting because the request
  model has no remote address field yet.

## Prioritized remediation plan

1. Complete admin bootstrap hardening:
   - add explicit operator CLI controls for bootstrap and recovery
   - add one-time bootstrap token lifecycle documentation
2. Continue reducing public listener attack surface:
   - isolate admin surfaces to loopback or local socket
   - retire legacy compatibility routes from public federation exposure
3. Improve abuse resistance:
   - add remote-IP-aware unauthenticated rate limiting
   - add targeted auth abuse regression tests
4. Harden release supply chain:
   - sign release artifacts
   - add provenance/attestation output
   - add explicit release-time license evidence
5. Expand automated security coverage:
   - add IaC/container scanning if container assets are introduced

## Secure coding checklist for follow-up

- Enforce configuration-backed auth policy in runtime handlers, not just config
  validation.
- Keep admin bootstrap separate from public registration.
- Route listeners by least privilege: client, federation, and admin surfaces
  should not share compatibility routers.
- Scope anonymous rate limits by remote address or equivalent abuse key.
- Treat release authenticity as a code-owned control: signatures and
  provenance belong in CI next to the existing SBOM and dependency-triage
  workflows.

## Re-test status

Follow-up workflow hardening landed on this branch after the initial audit:

- `.github/workflows/secret-scan.yml`
- `.github/workflows/dependency-vulnerability-triage.yml`
- `.github/workflows/sbom.yml`

Those changes close the earlier workflow-coverage gaps for secret scanning,
dependency vulnerability triage, and SBOM generation. Release signing and
provenance remain open findings.
