# SonarQube Cloud analysis runs in CI against the build's compilation database

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-27

Technical Story: 0.12.59; the owner asked for the SonarQube Cloud scan to run in CI.

## Context and Problem Statement

SonarQube Cloud analysed the repository with automatic analysis, configured by
`.sonarcloud.properties` (ADR-0229). Automatic analysis runs on SonarSource's side and works out
how each C and C++ file is compiled by itself; it never sees the flags, include paths, defines or
C++ standard the project is built with. SonarSource lists "missing issues" and needing "control
over the configuration" among the reasons to move a C or C++ project to CI-based analysis.

Should the analysis keep running on SonarSource's side, or run in this repository's CI?

## Decision Drivers

* The analyser should judge the code as it is compiled, `-std=c++26` and Meson's flags included.
* What is analysed, and how, should live in the repository and be tested, as ADR-0229 requires.
* The owner decided (2026-10-27).

## Considered Options

* CI analysis in Compilation Database mode: a workflow builds with Meson and passes the
  `compile_commands.json` Meson writes to the scanner.
* CI analysis with SonarSource's Build Wrapper wrapped around the build.
* Keep automatic analysis.

## Decision Outcome

Chosen option: CI analysis in Compilation Database mode. `.github/workflows/sonarcloud.yml` builds
with `scripts/build-linux.sh --builddir build-sonar --compile-only` (a full compile, so every file
the database names exists) and runs `SonarSource/sonarqube-scan-action`, pinned to a commit because
it receives `SONAR_TOKEN`. `sonar-project.properties` replaces `.sonarcloud.properties`: the same
ADR-0229 exclusions, plus the build directory and downloaded Meson subprojects, which automatic
analysis never saw. It runs on pushes to `main` and on pull requests from this repository; a fork's
pull request gets no secrets and is analysed once merged.

Since the job holds `SONAR_TOKEN`, its Python build tools (Meson, Ninja) install with
`pip install --require-hashes --only-binary :all:` from `requirements-build.txt`, the hash-locked
resolution of `requirements-build.in`: nothing is resolved at run time and no sdist's setup script
runs beside the token. Upgrading `pip` itself first is dropped for the same reason, and every action
the job uses, `actions/checkout` and `actions/setup-python` as well as the scan, is pinned to a
commit, since a tag can be moved.

Meson already writes the compilation database, and SonarSource accepts one from any tool; the Build
Wrapper would add a downloaded binary around the build for nothing this does not already give.

Automatic analysis must be switched off in the project's Administration > Analysis Method page
before this workflow first runs: SonarSource's CI analyses fail while it is on.

### Positive Consequences

* C and C++ are analysed with the project's real compile commands.
* The scan's scope and wiring are in the repository and held by
  `tests/tooling/test_sonarcloud_config.py`.

### Negative Consequences

* Each analysed push and pull request pays for a full build on a GitHub runner.
* Pull requests from forks are not analysed before merge.
* The analysis needs the `SONAR_TOKEN` repository secret; without it the job fails.
* The analyser's C++26 support is experimental and partial: `sonar.cfamily.experimental.cpp26.enabled=true`
  is required, or the scan refuses to start on a C++26 build, and some C++26 code may be analysed
  less thoroughly than the rest.
