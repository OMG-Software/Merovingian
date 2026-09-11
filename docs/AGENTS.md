# docs/ — Project Documentation

Every code change that adds, removes, or changes observable behavior requires a doc update
in the same branch. "Update the docs" means updating the specific files below — not creating
new documents.

## Mandatory on every branch

| Document | What to add/update |
|---|---|
| `../CHANGELOG.md` (repo root) | New `## X.Y.Z` section describing what changed |

## Update when the matching domain changes

| Document | Update trigger |
|---|---|
| `coding-rules.md` | A new project-wide coding rule is established |
| `security-coding-rules.md` | A security-relevant rule is added, changed, or removed in any module `AGENTS.md` file |
| `testing-standards.md` | A new testing convention is adopted |
| `versioning.md` | Version scheme changes; see also the version bump table |
| `auth-identity.md` | Auth, session token, or identity changes |
| `crypto-boundary.md` | Crypto interface, key management, or signing changes |
| `database-persistence.md` | Schema changes (migrations), store interface changes |
| `event-engine.md` | Event parsing, signing, hashing, authorization, or state resolution |
| `http-transport.md` | HTTP handling, TLS, rate limiting, or connection management |
| `media-repository.md` | Media upload, download, or deduplication |
| `threat-model.md` | New attack surface identified or an existing threat mitigated |
| `observability-audit.md` | New log fields, audit events, or observability changes |
| `trust-safety.md` | Policy engine changes |
| `architecture.md` | Module structure or cross-module dependency changes |
| `hardening.md` | Runtime hardening controls, seccomp, sandboxing, or build/link hardening changes |
| `user-manual.md` | A config key, default, reload policy, CLI flag, exit code, or admin API route is added or changed |
| `log-filtering.md` / `debug-logging.md` | A logger module name, log level behaviour, or diagnostic field changes |
| `dependencies/*.md` | A dependency is added, removed, upgraded, or its wrap/pin policy changes |
| `matrix-v1.19-client-server-api.md` | A Client-Server API endpoint is added, changed, or removed |
| `todos/capability-gaps.md` / `todos/production-milestone.md` | A tracked gap is closed or a new one is found |
| `../AGENTS.md` and the module's own `AGENTS.md` | A module is added: give it an `AGENTS.md`, a `CLAUDE.md` containing `@AGENTS.md`, and a row in the root `AGENTS.md` layout and index tables |
| `adr/index.md` | A design decision is made whose consequences outlive the change that prompted it — a constraint the code depends on but does not state locally, a rejected alternative that looks better in isolation, or a rule about how to write future code. Add a new ADR under `adr/`, and a line in `adr/index.md`. See [ADR-0000](adr/0000-record-architecture-decisions.md). |

## Do NOT create new documents for

- Per-feature implementation notes — those belong in `CHANGELOG.md`
- Debug notes or investigation results — those belong in commit messages
- Temporary analysis — work in conversation context, not files
### The one exception

Architecture Decision Records are the exception: each decision gets its own
immutable file under `docs/adr/`, numbered and never renumbered. Copy
[`adr/template.md`](adr/template.md), fill in status and date (both mandatory),
and add a line to [`adr/index.md`](adr/index.md) in the same commit. The format
is MADR 2.1.2; see [ADR-0001](adr/0001-use-markdown-architectural-decision-records.md)
for what was adopted and what was deliberately not.

Design rationale goes there, not into a general-purpose document.

## Formatting

All docs are CommonMark Markdown. Use:
- ATX headings (`#`, `##`, `###`)
- Fenced code blocks with language tags (` ```cpp `, ` ```sql `, ` ```bash `)
- Pipe tables with header rows
- No trailing whitespace; newline at end of file
