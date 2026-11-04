# tests/fuzz/ — Fuzz Targets

Fuzz targets exercise a single parsing or processing surface with arbitrary input.
Built only when `-Dbuild_fuzz=true` is passed to Meson.

## Existing targets

| File | Surface |
|---|---|
| `fuzz_canonicaljson.cpp` | Canonical JSON parser |
| `fuzz_http_request.cpp` | HTTP request parser |
| `fuzz_sync_filter.cpp` | Sync filter argument parser (`parse_filter_argument`) |
| `fuzz_config_parser.cpp` | Key-value config parser (`parse_key_value_config`) |
| `fuzz_stream_token.cpp` | Stream token decoder (`decode_stream_token`) |
| `fuzz_query_params.cpp` | Query-string parser and percent-decoder |
| `fuzz_srv_record.cpp` | Portable DNS SRV record parser (`parse_srv_records`) |
| `fuzz_multipart_upload.cpp` | multipart/mixed parser for a remote's federation media download (`parse_federation_media_multipart`); bytes before the first NUL are the Content-Type |
| `fuzz_url_preview_html.cpp` | URL preview HTML/OpenGraph extractor, content-type check and reference resolver |
| `fuzz_x_matrix_header.cpp` | `Authorization: X-Matrix` header parser (`parse_x_matrix_authorization_header`) |
| `fuzz_inbound_pdu.cpp` | Inbound PDU envelope parsers; first byte picks the room version |
| `fuzz_ipc_frame.cpp` | Federation worker IPC frame body decoders and JSON field extractors (not `IpcChannel::read_frame`, which needs a socket and key exchange) |
| `fuzz_appservice_yaml.cpp` | Application service registration YAML and JSON parsers |
| `fuzz_push_glob.cpp` | Push rule glob matcher, through `evaluate_push_rules`; bytes before the first NUL are the pattern |

`fuzz_input.hpp` holds the helpers that turn the byte buffer into strings and split it at the first NUL.
A target that takes two strings splits on NUL; keep to that so the seeds stay readable.

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
