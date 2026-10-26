# SonarQube Cloud ignores tests and tooling, and keeps the server, packaging and workflows

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-25

Technical Story: 0.12.51; SonarQube Cloud's quality gate ("Security Rating on New Code",
required A) failed PR #534 on findings in a CI script

## Context and Problem Statement

SonarQube Cloud was added to the repository with Automatic Analysis and no configuration, so it
analysed every tracked file and gated each pull request on the security rating of its new code.
On `main` it reported 170 vulnerabilities: 83 in `tests/`, 68 in `.github/`, 14 in `src/` and 5 in
`scripts/`. The root `llvm.sh`, a tooling script, carried 7 further issues of other types. PR #534
failed the gate on three path-traversal findings
in `scripts/filter_codeql_sarif.py`, a CI script that reads the SARIF path CI hands it.

The test findings are what tests do on purpose: world-writable temporary directories, hard-coded
test passwords and secrets, fixed-seed generators, `http://` fixtures, permissive modes on files a
test creates. The tooling findings are scripts trusting the arguments and files their own CI
supplies. Neither is attack surface of the server.

Which paths should SonarQube Cloud analyse, so that its gate stops blocking on test and tooling
code without hiding a finding that matters?

## Decision Drivers

* The gate must fail on new findings in code that ships or that runs with the project's
  privileges in CI, and on nothing else.
* What is excluded must be stated in the repository, reviewable in a diff, and tested.
* An exclusion must never be the way to quiet a real finding.

## Considered Options

* Exclude `tests/`, `scripts/`, `build.py`, `llvm.sh` and `.codex/` in `.sonarcloud.properties`.
* The same, and `.github/` too.
* Classify `tests/` as test code (`sonar.tests`) instead of excluding it.
* Change the quality gate in the SonarQube Cloud UI.

## Decision Outcome

Chosen option: "Exclude `tests/`, `scripts/`, `build.py`, `llvm.sh` and `.codex/`", because it
drops exactly the findings that are not attack surface and keeps every path that is.

`.sonarcloud.properties` (read by Automatic Analysis from the analysed branch) sets
`sonar.exclusions`. `tests/tooling/test_sonarcloud_config.py` fails if a tracked test or tooling
file is still analysed, or if anything under `src/`, `include/`, `packaging/`, `.github/`,
`migrations/` or `config/` is excluded.

### Positive Consequences

* Pull requests are gated on findings in the server, packaging and workflows only.
* The scope is in the repository and guarded by a test, not only in a web UI.

### Negative Consequences

* A real flaw in a test or script (a script that runs with CI secrets mishandling input, say) is
  no longer reported by SonarQube. CodeQL, gitleaks and review still cover those paths.
* The 68 `.github/` findings (actions not pinned to a commit SHA, `pip install` without
  `--only-binary`, dependencies without locked versions) and the 14 in `src/` remain open; they
  gate only a pull request that changes those lines, and need fixing or reviewing in SonarQube.
* The configuration is read from the analysed branch: a pull request opened before this change
  is gated without it until it is brought up to date with `main`.

## Pros and Cons of the Options

### Exclude `.github/` too

* Good, because no workflow edit is ever gated.
* Bad, because the workflows run with repository secrets and write tokens; unpinned actions and
  unlocked installs there are supply-chain findings, not noise.

### Classify `tests/` as test code

* Good, because tests would still be analysed by Sonar's test-code rules.
* Bad, because which rules run on test code is the analyser's choice and differs by language,
  so what is still reported is not stated anywhere in the repository; and it does nothing for
  `scripts/`, the path that failed PR #534.

### Change the quality gate in the UI

* Bad, because it weakens the gate for the server as well, and the change is invisible in the
  repository.

## Links

* Related to ADR-0226 (PR #534), which filters CodeQL's false positives on Catch2 tests.
