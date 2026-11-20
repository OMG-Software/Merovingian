# A ranges algorithm takes a typed value, never a bare string literal

* Status: accepted
* Date: 2026-11-20

Technical Story: the Fedora 44 and Fedora 45 RPM package jobs on `main` failed to compile
`src/homeserver/ClientServerRuntime.cpp` after PR #605.

## Context and Problem Statement

`std::ranges::find(names, "by_notification_count")`, where `names` is a `std::vector<std::string>`, built with clang and
older GCC, and failed with GCC 16, the compiler Fedora 44 and 45 ship, in `-std=c++26`:

```text
error: no match for call to '(const std::ranges::__find_fn) (const std::vector<std::string>&, const char [22])'
  ... required for the satisfaction of 'equality_comparable<_Up>' [with _Up = char (&)[22]]
  ... the required expression '(__t == __u)' is invalid
```

The constrained algorithms that compare elements with a value (`find`, `find_last`, `count`, `contains`, `remove`)
require `std::equality_comparable_with<element, value>`. That concept also needs each side to compare with itself, and
the type of a bare `"literal"` is a `char` array. C++26 removed `array == array` (P2865R6, ending the deprecation C++20
started), so GCC 16 rejects the call. `std::string == "literal"` still works; only the concept check fails.

Pull requests run the core CI gate (Ubuntu and FreeBSD, with clang and older GCC); the Fedora packages build with GCC
only in the merge queue and on `main` (ADR-0840). So the call merged unnoticed and broke `main`. About 45 calls in the
tests had the same form; the packages build without tests, so they had not failed yet.

How should code pass a string constant to a ranges algorithm, and how is the form kept out?

## Decision Drivers

* Every supported compiler must build every target, tests included.
* The pull request gate cannot be relied on to catch it: none of its compilers implements P2865 yet.
* Keep the call sites as short as they were.

## Considered Options

1. Pass a typed value: `"literal"sv` with `using namespace std::string_view_literals;`, `"literal"s`, or
   `std::string_view{"literal"}`; and have `scripts/reject-unsafe.sh` refuse a bare literal there.
2. Use the unconstrained `std::find(begin, end, "literal")`, which compares element by element and has no concept.
3. Add a GCC 16 job to the pull request gate and rely on it.
4. Fix the call sites only.

## Decision Outcome

Chosen option: 1. A `std::string_view` compares with itself and with `std::string`, so the concept holds on every
compiler, and the `sv` suffix adds two characters. `scripts/reject-unsafe.sh` reads each C and C++ file whole (so a
literal that the formatter wraps onto the next line is still seen) and refuses `std::ranges::find`, `find_last`,
`count`, `contains` or `remove` whose value argument is an unsuffixed string literal; the pre-commit hook and every CI
job that runs the gate stop it on any compiler. A production file scopes the `using namespace` to the function that
needs it; a test file may put it at file scope after its includes.

### Positive Consequences

* The pull request gate and the pre-commit hook catch the form, although none of their compilers rejects it.
* Production code and tests build on GCC 16.

### Negative Consequences

* The rule reads text, not C++: a first argument with a top-level comma inside template brackets
  (`std::map<int, int>{}`) hides a call from it. A typed value is never refused, but such a call would still reach the
  compiler.
* Another algorithm that compares with a value (`replace`, `remove_copy`) is not covered until it is added to the rule.

## Pros and Cons of the Options

### Unconstrained `std::find`

* Good, because it needs no suffix.
* Bad, because it returns to the iterator-pair form the code base moved away from, and still compiles a pointer
  comparison against `std::vector<char const*>` without complaint.

### A GCC 16 job on every pull request

* Good, because it catches every C++26 removal, not only this one.
* Bad, because the gate was kept small on purpose (ADR-0840), and it still lets the form be written and pushed; the gate
  rule stops it before the commit.

### Fix the call sites only

* Bad, because the next such call merges the same way, unseen until `main` fails.

## Links

* Related to [ADR-0840](0840-a-pull-request-runs-a-core-gate-and-the-merge-queue-runs-the-full-matrix.md)
