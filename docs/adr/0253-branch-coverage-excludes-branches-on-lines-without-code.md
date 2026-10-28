# Branch coverage excludes branches on lines without code

* Status: accepted
* Date: 2026-10-28

Technical Story: the SonarQube Cloud new-code coverage condition on PR #541

## Context and Problem Statement

ADR-0217 drops the compiler's exception edges from branch coverage with gcovr's
`--exclude-throw-branches`. gcov still reports branches on lines that hold no code of ours.
The largest is a function's closing brace, where GCC runs the destructors of the function's
locals. A long function with many locals collects dozens of such "conditions" on that one
line: on PR #541 three closing braces in `room_service.cpp` held 134 of the 467 uncovered
new-code conditions. No test can take them without injecting a failure, and SonarQube Cloud
(since ADR-0250 is given gcovr's report) fails its 80% new-code coverage condition on them.
Should branch coverage count them?

## Considered Options

* Exclude them with gcovr's `--exclude-unreachable-branches`, in both coverage jobs
* Keep counting them and lower the quality gate's coverage condition
* Mark each affected line excluded (`GCOVR_EXCL_LINE`)

## Decision Outcome

Chosen option: "exclude them with `--exclude-unreachable-branches`", because it removes exactly
the branches gcov places on lines without source code, keeps every decision branch and every
line count, and needs no annotation in the code. `coverage.yml` (Codecov) and `sonarcloud.yml`
(SonarQube Cloud) pass the same gcovr options, so the two reports agree. Held by
`tests/tooling/test_coverage_workflow.py` and `tests/tooling/test_sonarcloud_config.py`.

### Positive Consequences

* Branch coverage measures decisions in our code, as ADR-0217 intended.
* The quality gate's threshold stays where it is.

### Negative Consequences

* A branch gcov places on a line it considers empty is not reported even if a real decision
  were somehow attributed there; gcovr's heuristic is lines with no code, so a decision on a
  line of its own is unaffected.

## Pros and Cons of the Options

### Lower the coverage condition

* Bad, because it would also accept less coverage of real code.

### `GCOVR_EXCL_LINE` per line

* Bad, because every long function would need an annotation on its closing brace, and the
  next one written would be missed.
