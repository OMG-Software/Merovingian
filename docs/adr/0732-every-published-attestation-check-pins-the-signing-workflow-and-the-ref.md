# Every published attestation check pins the signing workflow and the ref

* Status: accepted (the `release.yml` signer for a tagged tarball is superseded by [ADR-0742](0742-build-test-and-package-platform-lists-and-a-tag-ships-what-latest-ships.md): every published file, the static tarball included, is attested by `packages.yml`)
* Date: 2026-11-12

Technical Story: run-3 audit of the 1.0.0 release candidate, needs-validation finding NV-2,
`F-supply-chain.release-verification.attestation-recipe-accepts-any-workflow-and-ref`.

## Context and Problem Statement

The release notes and `docs/release-process.md` told operators to check build provenance with
`gh attestation verify <file> --repo OMG-Software/Merovingian`. With `--repo` alone the check accepts an attestation made
by any workflow on any ref of the repository, and `packages.yml` attests what it builds on `codex/**` pushes and
same-repository pull requests; anyone who can push a branch can also add a workflow that attests any file. A file built
from unreviewed code would pass the published check. `scripts/run_complement.py` already pins the signer workflow and
the ref. What must a published recipe name?

## Decision Drivers

* The check must accept only an attestation from the workflow that builds that kind of file, on a release ref.
* A recipe in prose drifts; something must fail when one loses a flag.

## Considered Options

* Every recipe names `--signer-workflow` and `--source-ref`, and a tooling test keeps them
* Also stop `packages.yml` attesting on branches other than `main` and release tags
* Leave the recipe and tell operators to rely on the GPG signature

## Decision Outcome

Chosen option: the first. A tagged release's tarball is checked with
`--signer-workflow OMG-Software/Merovingian/.github/workflows/release.yml --source-ref refs/tags/v<version>`, its packages
with `.../packages.yml` and the same ref (a reusable workflow is the signer of what it attests, and the caller's tag is
the source ref), and a file of the rolling `latest` release with `.../packages.yml --source-ref refs/heads/main`. The
release notes fill `<version>` in from `meson.build`, which `check-tag` has matched to the tag. The documents say the
GPG signature is the primary check.

`AttestationRecipeTests` in `tests/tooling/test_release_workflow.py` reads every Markdown and workflow file except ADRs,
changelogs and the vendored spec (history, not instructions) and fails on a `gh attestation verify` command that lacks
`--repo`, a signer of `release.yml` or `packages.yml`, or a source ref of a release tag or `main`, or that names the wrong
workflow for a tarball or a package. A `gh attestation verify` named in prose without arguments is not a recipe.

### Negative Consequences

* The pinned check still passes for an attestation that `release.yml` made on a `v*` tag a writer pushed at a commit of
  their own, if that commit's workflow drops the `check-tag` ancestor check. Closing that needs the tag ruleset of the
  sibling finding (`release-environment.v-tag-rule-admits-a-tag-on-any-commit`), a repository setting the owner holds.

## Pros and Cons of the Options

### Also stop packages.yml attesting off main and tags

* Good, because fewer stray attestations exist.
* Bad, because it cannot stop a writer's own workflow file from attesting, so the recipe must pin the workflow and ref
  anyway; once it does, the stray attestations fail the check. Not done; worth revisiting only as tidiness.

### Rely on the GPG signature

* Bad, because the documents offered the attestation as a check of its own, and an operator who used only it was not
  protected.

## Links

* Related [ADR-0614](0614-the-release-signing-key-belongs-to-an-environment-and-a-tag-must-name-a-commit-on-main.md)
