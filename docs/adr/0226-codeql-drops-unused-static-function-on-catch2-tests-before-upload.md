# CodeQL drops cpp/unused-static-function on Catch2 tests before upload, and nowhere else

* Status: accepted
* Deciders: James Chapman
* Date: 2026-10-25

Technical Story: PR #532 drew 19 CodeQL review comments, every one this false positive

## Context and Problem Statement

Catch2's `SCENARIO` macro expands to a `static` function plus a `static` registrar
object whose constructor hands that function to the test registry. CodeQL's
`cpp/unused-static-function` (in the `security-and-quality` suite `codeql.yml` runs)
does not follow the registration, so it reports every scenario as unreachable,
together with every file-local helper that only scenarios call. By 0.12.46 `main`
carried thousands of these open alerts across `tests/` (405 in one conformance file)
and none in `src/` or `include/`, and each pull request touching tests drew review
comments for them. Real findings in the code scanning view drown in the noise.

How should the project stop the false positive without losing the rule where it means
something?

## Decision Drivers

* The rule is useful on production code, where an unreachable static function is dead
  code or a missed call.
* Every other rule must still see test code: a test can hold a real defect.
* No new third-party action in a workflow that holds `security-events: write`.
* An exclusion must be visible, reviewed and hard to widen by accident.

## Considered Options

* Dismiss the alerts one by one as false positives
* Exclude the rule in a CodeQL config (`query-filters`)
* Ignore `tests/` for analysis (`paths-ignore`)
* Analyse without uploading, drop the rule's results under `tests/` with a repository
  script, then upload
* The same, with a third-party SARIF-filter action

## Decision Outcome

Chosen option: "Analyse without uploading, drop the rule's results under `tests/` with a
repository script, then upload". The analyze step runs with `upload: never` and writes
its SARIF to `codeql-results/`; `scripts/filter_codeql_sarif.py` removes the results
whose rule is `cpp/unused-static-function` and whose file is under the top-level `tests/`
directory; `upload-sarif` publishes the rest under the same `/language:c-cpp` category.
Alerts already open on `main` close as fixed at the next analysis there.

The filter keeps anything it cannot place (a result with no location, or an absolute or
scheme-qualified URI), and refuses a report that is not SARIF without writing anything,
so the upload step fails rather than publishing an unfiltered report.

Rules this sets for future work:

* **The exclusion table in `filter_codeql_sarif.py` is the only place a CodeQL result may
  be suppressed.** Adding a pair to it is a new decision: give it its own ADR, scoped to a
  rule and a directory, never a rule alone.
* Never add `query-filters` or `paths-ignore` for this; either would silence production
  code or every rule on tests.

### Positive Consequences

* The rule still covers `src/` and `include/`, and every other rule still covers `tests/`.
* Pull requests stop drawing review comments for test scenarios.
* No new action runs with write access to security events; the filter is reviewed code
  with its own tests.

### Negative Consequences

* The workflow has two more steps, and the analyze action's own upload is not used.
* A genuinely unused static helper in a test file is no longer reported.

## Pros and Cons of the Options

### Dismiss the alerts one by one as false positives

* Good, because it changes nothing in CI.
* Bad, because every new scenario raises a new alert, so the dismissals never end and the
  noise returns on each pull request.

### Exclude the rule in a CodeQL config (`query-filters`)

* Good, because it is one line of configuration.
* Bad, because `query-filters` cannot be scoped to a path, so production code loses the
  rule too.

### Ignore `tests/` for analysis (`paths-ignore`)

* Good, because it is simple.
* Bad, because it removes every rule from test code, and for compiled C++ it does not
  apply to what the manual build compiles anyway.

### The same, with a third-party SARIF-filter action

* Good, because the filtering is already written.
* Bad, because it adds an external action to a job that can write security events, for
  logic small enough to keep in the repository and test.

## Links

* [docs/security-review-checklist.md](../security-review-checklist.md) — release checks for CodeQL
* [scripts/AGENTS.md](../../scripts/AGENTS.md) — the filter script
