# No std::format: the NetBSD libc++ has no `<format>` header

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-14

Technical Story: `netbsd-build-and-test` on PR #592 failed to compile `tests/support/TempDirectory.hpp` with
"'format' file not found"

## Context and Problem Statement

`unique_temporary_path` ([ADR-0753](0753-tests-never-write-a-fixed-name-in-the-shared-temporary-directory.md)) built
its name with `std::format`. It compiled on Linux, FreeBSD and OpenBSD, but the NetBSD CI image's libc++ does not
ship the `<format>` header, so the unit and integration test binaries failed to build there. Nothing in the tree had
included `<format>` before. How should code build strings from numbers?

## Considered Options

* Do not include `<format>` (`std::format`, `std::format_to`, `std::vformat`, `std::print`) in production code or
  tests; build strings with `std::to_string`, `std::to_chars` and string concatenation.
* Use `<format>` where it is available and fall back with a feature-test macro elsewhere.

## Decision Outcome

Chosen option: "Do not include `<format>`", because the supported NetBSD standard library lacks it, and a
feature-test fallback would mean two code paths of which CI builds each on one platform only. `std::to_chars` (integer
overloads) and `std::to_string` are available on every supported platform and are what the rest of the tree uses.
This is the same kind of rule as the one for `std::jthread` and `std::stop_token`
([ADR-0167](0167-no-jthread-or-stop-token-use-std-thread-and-stop-flag.md)).

### Negative Consequences

* Formatting with width, padding or a radix is written by hand, for example `std::to_chars(..., value, 16)`.

## Links

* Relates to [ADR-0167](0167-no-jthread-or-stop-token-use-std-thread-and-stop-flag.md)
* Relates to [ADR-0753](0753-tests-never-write-a-fixed-name-in-the-shared-temporary-directory.md)
