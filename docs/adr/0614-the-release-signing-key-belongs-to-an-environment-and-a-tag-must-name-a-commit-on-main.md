# The release signing key belongs to an environment, and a tag must name a commit on main

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-11

Technical Story: release-gate audit, `F-supply-chain.release-workflow.signing-key-reachable-from-any-ref`.

## Context and Problem Statement

`GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` were repository secrets handed to the signing job with no environment, so any
branch or tag pushed by anyone who can push ran a workflow that could hold them. `release.yml` also signed and published
for any commit whose `meson.build` named the tag's version, on `main` or not.

Where does the gate go, given that two workflows sign through one reusable workflow?

## Decision Drivers

* The key must be readable only from refs an environment admits.
* GitHub does not allow `environment:` on a job that calls a reusable workflow; only the called job can declare it.
* `on.workflow_call` cannot be handed an environment secret: a caller has no environment for it to come from.
* A published release must be built from a commit that reached `main`.

## Considered Options

* `environment: release` on the `sign-release-assets` caller job, as the finding proposed.
* `environment: release` on the called `sign` job, with callers passing named secrets.
* `environment: release` on the called `sign` job, with callers using `secrets: inherit`.

## Decision Outcome

Chosen option: "`environment: release` on the called `sign` job, with callers using `secrets: inherit`".

* The finding's placement is not valid workflow syntax, so the job that reads the key, `sign` in `sign-artifacts.yml`,
  declares the environment.
* A caller's `${{ secrets.GPG_PRIVATE_KEY }}` is empty once the secret lives only in the environment, so nothing names the
  key outside `sign-artifacts.yml`. `tests/tooling/test_release_workflow.py` fails if another workflow does.
* Both callers go through the one environment. `packages.yml` signs the rolling `latest` assets on pushes to `main`, so the
  environment must admit `main` as well as `v*` tags, or that signing fails closed.
* `check-tag` checks out with `fetch-depth: 0` and refuses a tag unless `git merge-base --is-ancestor "$GITHUB_SHA"
  origin/main` succeeds. Without the fetch depth `origin/main` does not exist on a tag build. A git failure also refuses.

The repository settings are the owner's to make, and until they are made the signing job has no key and fails:

1. Create the environment `release`, with a deployment rule admitting only `main` and tags matching `v*`.
2. Move `GPG_PRIVATE_KEY` and `GPG_PASSPHRASE` from repository secrets to that environment.
3. Decide on required reviewers. They hold every signing run, including each push to `main` for the rolling `latest`.
4. Add a tag ruleset limiting who may create `v*` tags.

### Negative Consequences

* `secrets: inherit` exposes the repository's other secrets to the called workflow. It is this repository's own file, and a
  secret reaches a runner only where a step names it.
* Anyone who can push to `main` can still change these files. The gate is against a pushed branch or tag, not against a
  writer to `main`, which the `main` ruleset covers.
* Neither workflow can be run from a test: the tests read the YAML and execute the ancestor step in a scratch repository.

## Links

* Refines [ADR-0597](0597-a-release-is-any-tag-that-names-the-meson-version-and-ships-what-meson-installs.md)
