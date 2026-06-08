# tests/fuzz/ — Fuzz Targets

Fuzz targets exercise a single parsing or processing surface with arbitrary input.
Built only when `-Dbuild_fuzz=true` is passed to Meson.

## Existing targets

| File | Surface |
|---|---|
| `fuzz_canonicaljson.cpp` | Canonical JSON parser |
| `fuzz_http_request.cpp` | HTTP request parser |

## Adding a new target

Add a new `fuzz_<surface>.cpp` that:
1. Accepts `const uint8_t* data, size_t size` (libFuzzer signature)
2. Feeds the raw bytes into the parsing surface under test
3. Asserts that the parser does not crash, corrupt memory, or loop infinitely
4. Does **not** assert a specific output — fuzzing is about stability, not correctness

Register the target in `tests/fuzz/meson.build`.

## Seed corpus

Place seed inputs in `tests/fuzz/corpus/<target>/`. Good seeds are short, valid inputs
that exercise different parse paths. The fuzzer engine extends them automatically.

## Regression tests

When a fuzz run finds a crash, add the minimal reproducer to
`tests/unit/test_<surface>.cpp` as a SCENARIO with `[fuzz][regression]` tags.
This ensures the crash is caught by the regular test suite without requiring the fuzzer to run.
