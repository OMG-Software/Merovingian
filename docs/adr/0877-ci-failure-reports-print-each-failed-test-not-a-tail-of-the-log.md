# CI failure reports print each failed test's section of the Meson log, not a tail of the whole log

* Status: accepted
* Date: 2026-11-24

Technical Story: an `asan-ubsan` run on the presence-flood pull request (run 44948590233, job 136981278297) said
"1 failed" and showed no failed assertion anywhere.

## Context and Problem Statement

When `meson test` fails, each CI job's "Catch2 failure report" step printed `testlog.txt` without the homeserver's
runtime log lines, then the last 300 lines of that (150 on NetBSD). Meson writes tests in the order they finish, so an
early failure, such as `integration-tests-shard-1-of-4`, is followed by every smoke test that finished after it, and
those pushed its Catch2 output out of the window. `--print-errorlogs` shows only the last 100 lines of a failed test,
which were runtime logging. How should a failure report find the failed assertion?

## Decision Drivers

* Where a failed Catch2 case (scenario, file and line, `FAILED:`, expansion, exception message) appears in the report
  must not depend on how early its test ran or how much passed after it.
* It must run unchanged on the Ubuntu, Debian, Fedora and AlmaLinux jobs and inside the FreeBSD, OpenBSD and NetBSD
  VMs, none of which is sure to have a `python3` on `PATH`.
* A broken run must not print an unbounded log.

## Considered Options

1. `scripts/catch2-failure-report.sh`: one POSIX `awk` pass over `testlog.txt` that keeps the section of each test
   whose `result:` is neither `exit status 0` nor `exit status 77` (Meson's skip), drops runtime log lines, and caps
   each test (first 400 and last 100 lines) and the whole report (4000 lines, summary included: a test that does
   not fit is cut further, or counted as not shown).
2. Raise the tail (say to 3000 lines).
3. Read `testlog.json` in Python, whose records carry a `result` of `FAIL`, `TIMEOUT` and so on.
4. Fix the order instead (run the integration shards last), or rely on `--print-errorlogs`.

## Decision Outcome

Chosen option: 1, run by every report step: `ci.yml`'s Linux and BSD jobs, `coverage.yml`, and both jobs of
`sanitizers.yml` (`tsan` had no report step). NetBSD passes `--exclude '^\[netbsd-diag\]'`. A job that builds with
`--no-tests` (`ubuntu-hardened-listener-coverage`) runs its Catch2 binary in its own step, whose log shows any failure,
and has no report step: it writes no `testlog.txt`.

* A tail of any length can lose a failure: the number of lines after it depends on what finished later, which changes
  with the platform, the sanitizer and the scheduling.
* `testlog.json` would be read more simply in Python, but the BSD VMs install only a versioned Python as Meson's
  dependency (see `check_expected_skips.py` in `scripts/AGENTS.md`), and a second implementation for them would drift.
  The text log's format is stable: each test opens with a `==== N/M ====` banner and closes with a 78-character rule,
  and `result:` holds Meson's `returncode_to_status` text.
* The order of tests is not the report's to fix, and `--print-errorlogs` cannot be told to skip runtime log lines.
* The script uses no `awk` interval expressions (`{4}`), which older releases of `mawk` and the BSDs' `awk` did not
  accept, and reads its patterns from the environment, since `awk -v` would process their backslashes.

### Negative Consequences

* The caps can leave out failure output, assertions included: a failed test with more than 500 lines of its own
  output shows its first 400 and last 100, and once the report nears 4000 lines a test is cut further or not shown.
  The report counts every gap and every test left out, and names `testlog.txt`, which holds the whole output: the
  `tsan` job uploads it, and elsewhere the failed test is run again locally.
* A change to Meson's text log format would make the report find no failed test. It then says so, rather than
  printing nothing, and `tests/tooling/test_catch2_failure_report.py` pins the format it reads.

## Links

* Covered by `tests/tooling/test_catch2_failure_report.py`, which also checks that every workflow's report runs the
  script and tails nothing.
