# CI fails on a Catch2 skip its job does not list

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-07

Technical Story: analysis finding T7 (58 `SKIP(` sites that pass silently)

## Context and Problem Statement

`meson test` reports a Catch2 test case that called `SKIP()` as passed. A CI runner that lacks a
precondition (Landlock, a `127.0.0.2` loopback alias, a libcurl with SMTP, a non-root user) therefore
goes green with the test not run, and nothing says so. How does a job learn that something it should
have exercised did not run, without making developers' local runs noisier?

## Decision Drivers

* A skip is legitimate on some runners (ASan cannot observe `mlock`, the BSDs have no seccomp) and a
  defect on others, so the answer depends on the job.
* Local `meson test` and direct binary runs must behave exactly as before.
* The check must fail closed: a crashed binary must not read as "no skips".

## Considered Options

* Parse `meson-logs/testlog.json` or the console output for skipped counts.
* Make skips failures (`--warn-about empty-test-case` style flags, or `SKIP` replaced by `FAIL`).
* Each job lists its expected skips; the test binaries write an XML report; a script compares them.

## Decision Outcome

Chosen option: the third.

* `tests/support/catch_report_arguments.hpp`, used by the three `test_main.cpp` files, adds
  `--reporter console --reporter merovingian-xml::out=<dir>/<binary>-<pid>.xml` to the command line **only**
  when `MEROVINGIAN_CATCH_REPORT_DIR` is set. Unset, the command line is untouched.
* `merovingian-xml` is `tests/support/NonCapturingXmlReporter.hpp`, Catch2's XML reporter with
  `shouldRedirectStdOut` off, registered by each `test_main.cpp`. Never use the stock `xml` (or `junit`,
  `sonarqube`, `teamcity`, `json`) reporter here: each asks Catch2 to redirect stdout, and Catch2 then puts its
  own buffer back on `std::cout` around every assertion it reports. That replaced the buffer the logger tests
  install with `std::cout.rdbuf()`, and their assertions after the first read nothing, on every job that set
  the variable. `catch-report-capture-tooling` runs those tests with the variable set.
* `scripts/check_expected_skips.py --job <name> --reports <dir>` reads every report, collects each
  `<Skip>` (test case name and message), and fails on any not matched by an entry of that job in
  `tests/expected_skips.json`. An entry names the test case, an optional message substring, and a
  mandatory one-line reason; entries live in groups that jobs combine.
* `build-linux.sh` and `build-bsd.sh` take `--skip-job <name>`, set the variable, run the tests, then
  run the script; a test failure and a gate failure both fail the script. Every workflow job that runs
  Catch2 passes its name; `postgres-integration.yml`, which runs a binary directly, calls the script itself.
* Fail closed (exit 2): no report directory or no report, a report that does not parse or lacks
  `OverallResults` (the run died), a bad allow-list, an unknown job.
* A listed skip that did not happen is a warning (`--strict-stale` makes it a failure), so lists are
  noticed to rot without a runner difference turning CI red.
* An entry with `"unverified": true` records behaviour of a runner that was assumed, not observed.

### Negative Consequences

* The allow-list must be kept in step with the runners; the tooling test checks that every entry names an
  existing test case and every job is used by a workflow.
* The report carries no `StdOut` or `StdErr` elements; the gate reads only `Skip` and the totals.
* The XML reporter's `Skip` element needs Catch2 3.3 or newer; with an older one the gate would see
  nothing. All supported builds use 3.14 or newer (wrap) or a distribution 3.x.

## Pros and Cons of the Options

### Parse meson's logs

* Bad, because Catch2's console output names skips only with `-s` and meson stores output of failing tests only.

### Make skips failures

* Bad, because a skip is the right outcome on some runners; the tests would then need per-runner build flags.

### Per-job expected-skip lists (chosen)

* Good, because it states what each runner is expected to lack, and a new missing capability fails loudly.
* Bad, because the lists are data to maintain.
