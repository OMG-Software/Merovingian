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

## Do NOT create new documents for

- Per-feature implementation notes — those belong in `CHANGELOG.md`
- Debug notes or investigation results — those belong in commit messages
- Temporary analysis — work in conversation context, not files

## Formatting

All docs are CommonMark Markdown. Use:
- ATX headings (`#`, `##`, `###`)
- Fenced code blocks with language tags (` ```cpp `, ` ```sql `, ` ```bash `)
- Pipe tables with header rows
- No trailing whitespace; newline at end of file
