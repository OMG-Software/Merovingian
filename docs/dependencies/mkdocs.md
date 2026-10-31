# MkDocs and Material for MkDocs dependency review

This note records the dependency review for MkDocs and the Material for MkDocs
theme, which build the documentation site.

## Decision

MkDocs and Material for MkDocs are accepted as documentation tooling. They are
never built into, linked into, or shipped with any Merovingian binary or
package; they run only in the documentation site workflow and on developer
machines that build the site.

## Why it is needed

The documents under `docs/` are published as a static site on GitHub Pages
(see [ADR-0101](../adr/0101-build-the-documentation-site-on-every-branch-but-publish-only-from-main.md)).
MkDocs renders the Markdown and validates links; Material provides the theme,
search, admonitions and Mermaid diagram rendering.

## Security boundary

- Direct dependencies are listed in `requirements-docs.in`. The lock file
  `requirements-docs.txt` pins every package, direct and transitive, to an
  exact version with SHA-256 hashes, and CI installs it with
  `pip --require-hashes --only-binary :all:`, so no package's setup script runs
  (ADR-0313).
- `tests/tooling/test_docs_site.py` fails if any locked requirement lacks an
  exact pin or a hash, if `mkdocs-material` is pinned below 9.7.7, the first
  release fixing the search-suggestion DOM XSS GHSA-xvg9-69gf-fjrf, or if
  `certifi` (transitive, via `requests`) is pinned below 2026.10.19.
  GHSA-6q48-6c7w-9gw2: releases before 2026.10.18 bundle emSign root CAs whose
  intermediate CA keys were compromised; the advisory's version range names
  2026.10.19 as the first patched release, and dependency scanners enforce
  that range, so 2026.10.19 is the floor. `requirements-docs.in` floors `certifi`
  so a regenerated lock cannot resolve back to a vulnerable release.
- The site build job runs with `contents: read` only. The Pages deploy job
  holds `pages: write` and `id-token: write`, runs only for `main`, and
  executes no third-party Python.
- The SBOM-backed dependency triage workflow scans the locked packages along
  with the rest of the repository.
- The only project code MkDocs runs is `scripts/mkdocs_site_hooks.py`.

## Maintenance and platform posture

To upgrade, edit `requirements-docs.in` and regenerate the lock:

```bash
uv pip compile requirements-docs.in --universal --python-version 3.13 --generate-hashes --only-binary :all: -o requirements-docs.txt
```

Then build the site locally with `mkdocs build --strict` (see
[dev-environment.md](../dev-environment.md#documentation-site)) and record
the upgrade in `CHANGELOG.md`.
