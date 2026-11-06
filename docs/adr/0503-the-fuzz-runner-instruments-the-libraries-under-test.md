# The fuzz runner instruments the libraries under test

* Status: accepted
* Deciders: James Chapman
* Date: 2026-11-04

## Context and Problem Statement

`tests/fuzz/meson.build` gives each target `-fsanitize=fuzzer,address,undefined`, but a target
links the project's static libraries, and `scripts/run-fuzz-targets.sh` built those with no
sanitizer and no coverage counters. A first run of the new targets showed the effect: libFuzzer
reported 263 counters for `fuzz-multipart-upload`, the target file alone. The parser under test had
none, so the fuzzer saw no branch in it, and a heap overflow inside it would not have been reported
by AddressSanitizer either. Every target in the runner ran blind in this way, and a clean run proved
little.

## Considered Options

* Build the whole tree with `-Db_sanitize=address,undefined` and `-fsanitize-coverage` counters in
  the runner (chosen)
* Compile the sources of each target into the target, instead of linking the libraries
* Leave the libraries plain and rely on the targets' own flags

## Decision Outcome

Chosen option: instrument the whole fuzz build in the runner, because it is one change in one
place, it covers every module a target links, and the targets still call the real library code. The
same `fuzz-multipart-upload` then reports 826346 counters.

Compiling each parser's sources into its target would instrument only that file's own code and would
make a second copy of the parser: a target must call the real one. Leaving the libraries plain looks
cheaper and keeps the runner's old build, but it is the state that made a clean run mean little.

A build that is not made through the runner (`-Dbuild_fuzz=true` alone) still has plain libraries and
its targets still run; they are weaker, not broken. `tests/tooling/test_fuzz_targets.py` pins the
runner's flags and that it runs every target registered in `tests/fuzz/meson.build`.

### Consequences

* The fuzz build is slower and the targets run several times slower per input than with plain
  libraries (936 exec/s against 3585 for `fuzz-multipart-upload` in a local run).
* The CI duration per target (120 s on a push, 900 s on the weekly run) buys fewer inputs than it
  did, and there are now fourteen targets, so the push job takes about twice as long as with seven.
* The runner now needs `-Db_lundef=false` for the sanitizer link; do not drop it.
