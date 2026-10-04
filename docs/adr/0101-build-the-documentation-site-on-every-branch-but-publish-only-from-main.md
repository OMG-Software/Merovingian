# Build the documentation site on every branch, but publish only from main

* Status: accepted
* Date: 2026-10-04

Technical Story: [OMG-Software/Merovingian#500](https://github.com/OMG-Software/Merovingian/pull/500)

## Context and Problem Statement

The documents under `docs/` are published as a GitHub Pages site built with
MkDocs Material from `mkdocs.yml`. Every branch already has to update the
relevant documents, so every branch can also break the site: a renamed
document, a link to a file that moved, or a new page nobody added to the
navigation. How should branches interact with the published site?

The documents are written to be read in the repository, so they link to source
files, workflows, module `AGENTS.md` files and the vendored Matrix spec mirror,
none of which the site publishes. Under `mkdocs build --strict` each of those
links is a broken-link warning.

## Decision Drivers

* A branch that breaks the site must fail CI before it merges, not after.
* The public site must describe what is on `main`, never unmerged work.
* Reviewers should be able to see the rendered site for a branch.
* The site is a security-first project's public face: the build must not run
  unpinned or unverified third-party code, and the deploy credentials must be
  as narrow as possible.

## Considered Options

* Build strictly on every branch and pull request, keep the rendered site as a
  workflow artifact, and deploy to Pages only from `main`.
* Publish a live preview per branch under `/preview/<branch>/` on a `gh-pages`
  branch, alongside `main` at the site root.
* Deploy the live site from whichever branch was pushed last.
* Build and deploy only from `main`, as the first version of the workflow did.

## Decision Outcome

Chosen option: build strictly on every branch and pull request, deploy only
from `main`, because it is the only option that both catches a broken site
before merge and keeps the public site equal to `main`.

* `.github/workflows/pages.yml` runs on every push and pull request with no
  path filter. It runs `tests/tooling/test_docs_site.py` and then
  `mkdocs build --strict`, and uploads `site/` as the `docs-site` artifact.
* Only the `deploy` job, gated on `refs/heads/main` and not `pull_request`,
  holds `pages: write` and `id-token: write`. The `build` job has
  `contents: read` only.
* `requirements-docs.txt` is a hash-locked resolution of
  `requirements-docs.in` covering every transitive package, and CI installs
  it with `pip --require-hashes`.
* `scripts/mkdocs_site_hooks.py` rewrites links to files the site does not
  publish so they open on GitHub at the commit the site was built from, and
  links into `docs/matrix-v1.19-spec/` so they open the same section of
  `https://spec.matrix.org/v1.19/`. A link whose target exists nowhere in the
  repository is left alone, so the strict build still rejects it.
* `tests/tooling/test_docs_site.py` fails when a published document has no
  navigation entry in `mkdocs.yml`. ADR records are exempt; the ADR index
  links to them.

### Positive Consequences

* Broken links, missing navigation entries and theme warnings fail the branch
  that introduced them.
* Documents keep their repository-relative links. Nobody has to write a
  different link for the site than for GitHub.
* A reviewer can download the rendered site for any branch.

### Negative Consequences

* There is no browsable live preview of a branch; the artifact has to be
  downloaded and opened locally.
* Branches pushed to this repository build the site twice when a pull request
  is open: once for the push and once for the pull request merge ref.
* Adding a document under `docs/` now also means adding it to the `mkdocs.yml`
  navigation or to `exclude_docs`.

## Pros and Cons of the Options

### Live preview per branch

* Good, because reviewers get a browsable URL.
* Bad, because unmerged work is published on the project's public domain,
  where search engines index it and readers cannot tell it from the real site.
* Bad, because Pages must deploy from a `gh-pages` branch that every branch
  run can write to, so every branch build needs `contents: write`.
* Bad, because previews of deleted branches need a separate pruning job.

### Deploy from whichever branch was pushed last

* Good, because it is the simplest workflow.
* Bad, because the public site shows unmerged work and changes with every push.

### Build and deploy only from main

* Good, because no extra CI runs.
* Bad, because a branch that breaks the strict build merges cleanly and only
  fails the deploy on `main`, after the fact.
