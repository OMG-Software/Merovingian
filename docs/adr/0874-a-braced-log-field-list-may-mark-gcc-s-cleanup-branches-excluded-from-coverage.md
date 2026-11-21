# A braced log-field list may mark GCC's cleanup branches excluded from coverage

* Status: accepted
* Date: 2026-11-21

## Context and Problem Statement

A structured log call takes its fields as a braced list, `log_diagnostic(event, {{"user_id", *user, false}, ...})`.
For such a list of `StructuredLogField` (two `std::string`s each), GCC emits a loop that destroys the fields already
built when building a later one throws. gcov labels that loop's test as an ordinary decision branch, not an exception
edge, so `--exclude-throw-branches` ([ADR-0217](0217-branch-coverage-excludes-compiler-exception-edges.md)) keeps it, and
it gives the first field's line, which only that cleanup path reaches, a count of zero. Every braced field list in
`ClientServerRuntime.cpp` shows the call line with 4 of 6 conditions covered and, in a list of two or more fields, the
first field's line uncovered; `request.auth.accepted`, written on every authenticated request, is one. No test can reach
the path without failing an allocation. A change whose new code is mostly such calls cannot reach SonarQube Cloud's 80%
coverage on new code: pull request 611 added 12 coverable lines, three of them TURN log calls, and stood at 74.2%. How is
that told apart from code a test should cover?

## Decision Drivers

* The testing standards allow an exclusion marker only for code that is genuinely unreachable, with the reason beside it.
* A real decision on a field's line (a `cond ? a : b` value) must stay measured.
* The quality gate is the built-in "Sonar way", which cannot be edited, and a project-wide change weakens every pull
  request.

## Considered Options

* Mark the call line `GCOVR_EXCL_BR_LINE` and the first field's line `GCOVR_EXCL_START`/`GCOVR_EXCL_STOP`, where the
  artefact shows
* Write the calls another way (an `initializer_list` parameter, a typed helper per line, `push_back`)
* A custom quality gate with a lower coverage threshold
* Exclude `ClientServerRuntime.cpp` from coverage (`sonar.coverage.exclusions`)

## Decision Outcome

Chosen option: mark the call line and the first field's line, because it removes only what GCC generated: the call's own
line still counts as covered, every other field's line and its decisions are still measured, and nothing outside the
marked call changes. A call whose fields gcov reports fully covered needs no marker.

The markers are written as `ClientServerRuntime.cpp`'s TURN calls show them: a comment above the call naming this ADR, a
trailing `// GCOVR_EXCL_BR_LINE` on the line that opens the call, and, for a list of two or more fields, `//
GCOVR_EXCL_START` and `// GCOVR_EXCL_STOP` on their own lines around the first field only. clang-format leaves that
layout as it is. A trailing `// GCOVR_EXCL_LINE` on the field would do the same, but pushes a long aligned row past the
120-column limit.

### Positive Consequences

* The TURN log calls reach full coverage on the lines gcov can count, and the gate passes without being loosened.
* The reason for every marker is one ADR away.

### Negative Consequences

* A marker hides a real untested branch if one is ever written on the marked line. Never put a decision (`?:`, `&&`,
  `||`) on the line that opens the call, nor in the first field of a marked list: put it in a later field.
* Only new calls that need it are marked; the many unmarked braced lists in older code keep the artefact, which a change
  that adds enough other covered lines absorbs.

## Pros and Cons of the Options

### Write the calls another way

* Bad, because each shape measured with `gcc-14 -O2 --coverage` and gcovr kept a partial branch, or moved it into the
  helper: an `initializer_list` parameter still builds an array of fields at the call, and `push_back` has the vector's
  growth branch.

### A custom quality gate

* Bad, because it lowers the bar for every pull request to pass one, and may need a paid plan.

### Exclude the file from coverage

* Bad, because `ClientServerRuntime.cpp` holds most of the client-server API and would no longer be measured at all.

## Links

* Refines [ADR-0217](0217-branch-coverage-excludes-compiler-exception-edges.md): a compiler exception path gcov does not
  label as one is marked by hand, call by call.
* See [ADR-0871](0871-turn-credential-requests-log-under-their-own-turn-module.md): the TURN log calls are the first marked.
