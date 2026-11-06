# Group external headers before the standard library

* Status: accepted
* Date: 2026-11-06

## Context and Problem Statement

The formatter recognised only selected third-party directory prefixes. It put
flat library headers such as `<sodium.h>` after standard headers and treated
unknown names without punctuation as standard. The project owner specified
matching header, project headers, third-party headers, then STL headers, and
confirmed that OS headers belong with external headers before STL.

## Considered Options

* Keep spelling-based groups that split external headers across categories.
* List every external dependency and treat other simple names as standard.
* Identify standard library header names explicitly and group all other external
  headers before them.

## Decision Outcome

Chosen option: identify standard library header names explicitly. The matching
header remains first through clang-format's main-header handling. Other project
headers follow, then third-party and OS headers, then standard library headers.
Use a blank line between groups and case-sensitive alphabetical sorting within
each group. Include standard C compatibility headers in the standard library group.

The maintained rule is in [coding rules](../coding-rules.md#calls-formatting-and-includes).
The name lists come from the C++ working draft's
[library header tables](https://eel.is/c++draft/headers) and
[C compatibility header table](https://eel.is/c++draft/support.c.headers).
This is a formatting classification, not a claim that every listed facility is
available on every supported platform.

### Positive Consequences

* Flat library names and OS paths follow the owner's requested order.
* New external dependencies do not need formatter exceptions.
* Regression tests run the formatter against mixed header groups.

### Negative Consequences

* The standard header list needs maintenance when new standard headers are adopted.
* The formatter tests skip when clang-format is unavailable; such a run does not
  verify include ordering.
