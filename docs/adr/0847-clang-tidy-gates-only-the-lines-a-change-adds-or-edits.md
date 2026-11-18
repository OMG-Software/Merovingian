# clang-tidy gates only the lines a change adds or edits

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-18

## Context and Problem Statement

The `clang-tidy` job in `static-analysis.yml` was meant to check the C++ translation units a pull request changed. The checkout
is one commit deep, so the three-dot `git diff FETCH_HEAD...HEAD` it ran had no merge base and failed, and `|| true` turned
that failure into "no changed files": clang-tidy never ran on a pull request, and the required check always passed. Fixing the
diff made it run, and it then failed on errors that were already in the files it checked (in
`tests/integration/test_server_startup_hardening_flow.cpp`: public members, an empty `catch`, an unchecked `optional`, and a
Catch2 `SCENARIO`). Once the check runs, which code should a pull request answer for?

## Considered Options

* Whole changed files: clang-tidy on every changed translation unit, every diagnostic counts.
* Changed lines: `clang-tidy-diff` runs clang-tidy on every changed translation unit with a line filter, so only diagnostics on
  added or edited lines count.
* Leave clang-tidy off on pull requests until the existing findings are fixed.

## Decision Outcome

Chosen: changed lines. The step pipes `git diff -U0` against the pull request's or the merge queue's base commit into the
`clang-tidy-diff` script of the same LLVM release as the installed clang-tidy; it exits 1 when any run reports an error or
times out, and the step runs under `bash`, so a failed diff fails the step instead of reading as "nothing changed". Headers are
not run on their own, as before; a diagnostic in a header counts only when the header's changed lines are in the filter, which
they are not for a `.cpp`-only run.

`tests/.clang-tidy` turns off `misc-use-anonymous-namespace`: every Catch2 `SCENARIO` expands to a `static` function
(`dummyFunctionN`), so any new scenario would fail it, and the expansion is Catch2's, not code this project can change. The
check stays on for `src/`.

Rejected:

* **Whole changed files.** A one-line edit would make its author fix every older finding in the file, and the first pull
  request to touch a file pays for all of its history. That turns a small change into an unrelated cleanup, or invites `NOLINT`
  to get past it.
* **Off until the debt is fixed.** No one is assigned the debt, and new code would keep adding to it unchecked in the meantime.

## Consequences

* Findings already in a file stay until someone edits those lines or fixes them on purpose; the gate stops new ones.
* Editing a line that already has a finding makes the pull request fix it.
* A diagnostic that clang-tidy reports on an unchanged line because of a changed line elsewhere (for example a changed
  declaration) is filtered out; the line filter cannot see that link.

## Links

* Related [ADR-0840](0840-a-pull-request-runs-a-core-gate-and-the-merge-queue-runs-the-full-matrix.md)
