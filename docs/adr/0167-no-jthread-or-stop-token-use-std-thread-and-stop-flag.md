# Use `std::thread` and `StopFlag`, never `std::jthread` or `std::stop_token`

* Status: accepted
* Date: 2026-10-17

Technical Story: the 0.12.28 branch (17 October 2026 conformance audit, wave 1) added
`homeserver::PeriodicJob` on `std::jthread` and `std::stop_token`, and the FreeBSD package job
failed to compile it.

## Context and Problem Statement

The project builds with the base-system clang and libc++ on FreeBSD and OpenBSD. That libc++
(FreeBSD's is LLVM 19.1.7) does not provide `<stop_token>` or `std::jthread`: libc++ shipped them
behind `-fexperimental-library` until LLVM 20. Linux builds use libstdc++, which has both, so code
that uses them passes every Linux job and fails only on the BSDs. This has now happened four
times: three times in tests (fixed by `tests/support/joining_threads.hpp`) and once in production
code. The rule was written down only in `tests/support/AGENTS.md`.

How should background threads be written so they build on every supported platform?

## Considered Options

* `std::thread`, joined from RAII, with a project `StopFlag` (an atomic bool) for stop requests.
* Keep `std::jthread` and `std::stop_token`, and pass `-fexperimental-library` on libc++.
* Keep `std::jthread` and `std::stop_token` on Linux only, behind a feature-test macro.

## Decision Outcome

Chosen option: `std::thread` with `StopFlag`, because it builds on every supported toolchain
without changing compiler flags or keeping two code paths.

`homeserver::PeriodicJob` owns a `std::thread` and joins it in `stop()` and its destructor.
`stop()` sets its `StopFlag` under the job's mutex before notifying its condition variable, so a
run loop cannot test the flag, miss the notification and then sleep for its whole delay. A job
receives the `StopFlag` by const reference and polls it between units of work. Tests use
`JoiningThreads`.

### Positive Consequences

* One code path builds on Linux, FreeBSD, OpenBSD and NetBSD.
* The rule now sits in `docs/coding-rules.md`, where production code is written, not only beside
  the test helpers.

### Negative Consequences

* A `StopFlag` cannot wake a thread blocked in a condition-variable wait on its own; the owner
  must also notify (as `PeriodicJob::stop()` does). `std::condition_variable_any` with a stop
  token did that implicitly.

## Pros and Cons of the Options

### `-fexperimental-library` on libc++

* Bad, because it opts the whole build into unstable libc++ features and ABI.
* Bad, because it changes the build for one header and must be kept in step with each BSD's LLVM.

### `std::jthread` on Linux only, behind a feature-test macro

* Bad, because it keeps two implementations of the same thread lifecycle, and the BSD one would be
  exercised only by BSD CI.
