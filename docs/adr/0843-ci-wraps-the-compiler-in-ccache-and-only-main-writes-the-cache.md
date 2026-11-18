# CI wraps the compiler in ccache, and only `main` writes the cache

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-18

## Context and Problem Statement

Every Linux build job ran `hendrikmuhs/ccache-action`, which restored and saved a cache, yet `ccache -s` at the end of
`ubuntu-build-and-test` reported `Cache size (GB): 0.0`. `scripts/build-linux.sh` passes `CC` and `CXX` (default `clang`,
`clang++`) to `meson setup`, and Meson adds ccache only when it chooses the compiler itself. So no job used the cache, and
each compiled all 1,169 targets from scratch: 34 minutes on Ubuntu.

## Considered Options

* Make `build-linux.sh` prefix the compiler with ccache whenever ccache is installed.
* Set `CC="ccache <compiler>"` and `CXX="ccache <compiler>"` in the CI jobs that restore a ccache.
* Use the action's `create-symlink`, which puts ccache's compiler links first in `PATH`.

## Decision Outcome

Chosen: set `CC` and `CXX` in the job's `env`, wrapping the compiler that job already used, in each job that restores a ccache.
Those are the Linux build and test jobs, the sanitizers, fuzz and coverage. The action's `max-size` is `1G`, and
`save: ${{ github.ref == 'refs/heads/main' }}`, so only a run on `main` writes the cache, and pull request and merge-queue runs
restore `main`'s.

ccache is not added to `codeql.yml` (CodeQL must see every compile to extract it), `static-analysis.yml` or
`reproducible-build.yml`, whose purpose is to compile from source. `packages.yml` and `release.yml` keep the ccache steps they
already had, unchanged; whether those package builds should use a cache is a separate decision.
`tests/tooling/test_ci_tiers.py` fails on a job of `ci.yml`, `coverage.yml`, `sanitizers.yml` or `fuzz.yml` that restores a
ccache without wrapping both compilers or that saves off `main`, and on ccache in any of the three workflows above.

Rejected:

* **Changing `build-linux.sh` to add ccache itself.** Developer, CodeQL and package builds that call it would start using
  ccache silently, including the ones above that must not. The script only learned to accept a launcher in `CC`: it checks
  that the first word is on `PATH`.
* **`create-symlink`.** It wraps whichever compiler is found by name in `PATH`, and the container jobs (Fedora, AlmaLinux,
  openSUSE) keep their links in different places; an explicit `CC` is the same everywhere and visible in the job.

## Consequences

* The first run on `main` after this change fills the caches; later pull requests compile only what changed.
* A pull request no longer writes caches. The repository's 10 GB cache budget holds one set from `main` instead of being evicted
  by every pull request run.
* A job that adds ccache-action must also wrap `CC` and `CXX`, or the action does nothing again.
