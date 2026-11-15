# Change obligations

What every branch must carry besides code. Sources: root `AGENTS.md`,
[docs/AGENTS.md](../../../../docs/AGENTS.md), [docs/versioning.md](../../../../docs/versioning.md) and
ADR-0000/0001/0543/0740/0741. Only the formats are checked by tooling (`test_changelog_format.py`,
`test_packages_workflow.py`). Whether each obligation was met is for the reviewer.

## CHANGELOG.md

- A bullet for this change under the right heading of the right version: `## Features` for new behaviour,
  `## Security Fixes` for vulnerabilities and DoS paths (audit findings included), `## Bug fixes` for every other
  correction (test and CI fixes included). `## Release notes` is one paragraph an operator must read before
  upgrading.
- The bullet says what changed for the operator or client, not how, and ends with its ADR or finding ID.
- `CHANGELOG-pre-release.md` is frozen (ADR-0740). Any diff to it is a finding.
- A docs-only branch adds its bullets to the **current** version's entry and does not bump.

## Version

- One bump per branch, BUILD + 1, except documentation-only changes (ADR-0464). `AGENTS.md` and coding-guidance
  edits count as documentation. Any code, build, packaging or test change means the bump applies.
- Every place agrees with `meson.build`. The list is in `docs/versioning.md`: `src/main.cpp`,
  `src/db_migrate.cpp`, the FreeBSD manifest, the NetBSD Makefile, three RPM specs (each also with a new dated
  `%changelog` entry), the `scripts/build-*.sh` scripts, and the CHANGELOG heading.
- The number must not be taken by another open branch. Check before approving.

```bash
git show origin/main:meson.build | grep -m1 "version:"; grep -m1 "version:" meson.build
grep -n 'version = std::string_view' src/main.cpp src/db_migrate.cpp
grep -n '^Version:' packaging/{rpm,rhel,opensuse}/merovingian.spec
grep -nE '^VERSION=' scripts/build-*.sh
for r in $(git for-each-ref --format='%(refname)' refs/remotes/origin); do
  git show "$r:meson.build" 2>/dev/null | grep -m1 -o "version: '[^']*'" | sed "s|^|$r |"; done | sort -k3 | tail
```

## Docs

Every change to observable behaviour updates its owning doc in the same branch. Update existing files; do not add
per-feature notes. Table (from `docs/AGENTS.md`):

| Change | Doc |
|---|---|
| Project-wide coding rule | `docs/coding-rules.md` |
| Security rule in a module `AGENTS.md` | `docs/security-coding-rules.md` too |
| Testing convention | `docs/testing-standards.md` |
| Auth, sessions, identity | `docs/auth-identity.md` |
| Crypto interface, keys, signing | `docs/crypto-boundary.md` |
| Schema, migrations, store interface | `docs/database-persistence.md` |
| Event parse, sign, hash, auth, state resolution | `docs/event-engine.md` |
| HTTP, TLS, rate limits, connections | `docs/http-transport.md` |
| Media | `docs/media-repository.md` |
| New attack surface or mitigated threat | `docs/threat-model.md` |
| Log fields, audit events | `docs/observability-audit.md` |
| Policy engine | `docs/trust-safety.md` |
| Module structure, cross-module dependencies | `docs/architecture.md` |
| Hardening, seccomp, sandbox, build flags | `docs/hardening.md` |
| Config key, default, reload policy, CLI flag, exit code, admin route | `docs/user-manual.md` |
| Logger module or diagnostic field | `docs/log-filtering.md`, `docs/debug-logging.md` |
| Dependency change | `docs/dependencies/*.md` |
| Client-Server endpoint | `docs/matrix-v1.19-client-server-api.md` |
| Gap closed or found | `docs/todos/capability-gaps.md`, `docs/todos/production-milestone.md` |
| New module | module `AGENTS.md`, its `CLAUDE.md` with `@AGENTS.md`, and rows in the root `AGENTS.md` tables |
| Doc added, removed or renamed under `docs/` | `mkdocs.yml` nav |
| Something the review skill cites changed | `.agent/skills/merovingian-review/` |

The usual miss: the user manual and CHANGELOG are updated, but the owning guide is not. Also check for comments
or docs that the change makes false.

## ADR

- Needed when a future reader would otherwise undo the decision by accident. That covers a constraint the code
  relies on but does not state, a rejected alternative that looks better in isolation, and a rule about how to
  write future code. Not needed for a fact with no alternative, or for spec-mandated behaviour.
- Copied from `docs/adr/template.md`, with `* Status:` and `* Date:`. Numbered above every number that exists on
  **any** branch, never reused. A line goes in `docs/adr/index.md` in the same commit. Supersession is marked,
  never deleted.
- A diff that reverses an existing ADR's decision without superseding it is a finding.

```bash
for r in $(git for-each-ref --format='%(refname)' refs/heads refs/remotes/origin); do
  git ls-tree --name-only "$r" docs/adr/; done | grep -oE '[0-9]{4}-' | sort -u | tail -3
git diff --name-status <base>...<head> -- docs/adr
git diff <base>...<head> | grep -oE 'ADR-[0-9]{4}' | sort -u | sed 's/ADR-//' | while read n; do
  ls docs/adr/$n-*.md >/dev/null 2>&1 || echo "cited but missing: ADR-$n"; done
```

## Pull request description

Headings: **Summary**, **What changed** (bullets), **Why it changed**, **CI tests** (bullets of modified tests,
then bullets of new tests). Check that the CI tests list matches the test files in the diff, and that every claim
in the description is supported (see SKILL.md Step 1).

## Branch

Not `main`. Based on a current `origin/main`, or on the PR it is stacked on, with the merge order stated.
