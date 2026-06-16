cpp = meson.get_compiler('cpp')

# libFuzzer entry points (LLVMFuzzerTestOneInput) require -fsanitize=fuzzer
# at compile and link time. Pair with address+undefined for sharper crash
# signal in CI runs. ASan/UBSan recovery is disabled so any finding aborts
# the run.
fuzz_sanitizer_args = ['-fsanitize=fuzzer,address,undefined', '-fno-sanitize-recover=all']

if not cpp.has_argument('-fsanitize=fuzzer')
  error('build_fuzz=true requires a compiler that supports -fsanitize=fuzzer (clang)')
endif

fuzz_targets = [
  executable(
    'fuzz-canonicaljson',
    sources: files('fuzz_canonicaljson.cpp'),
    include_directories: inc,
    cpp_args: fuzz_sanitizer_args,
    link_args: fuzz_sanitizer_args,
    link_with: [canonicaljson_lib],
  ),
  executable(
    'fuzz-http-request',
    sources: files('fuzz_http_request.cpp'),
    include_directories: inc,
    cpp_args: fuzz_sanitizer_args,
    link_args: fuzz_sanitizer_args,
    link_with: [http_lib],
  ),
  executable(
    'fuzz-sync-filter',
    sources: files('fuzz_sync_filter.cpp'),
    include_directories: inc,
    cpp_args: fuzz_sanitizer_args,
    link_args: fuzz_sanitizer_args,
    link_with: [sync_lib, canonicaljson_lib, observability_lib, platform_lib],
  ),
  executable(
    'fuzz-config-parser',
    sources: files('fuzz_config_parser.cpp'),
    include_directories: inc,
    cpp_args: fuzz_sanitizer_args,
    link_args: fuzz_sanitizer_args,
    link_with: [config_lib],
  ),
  executable(
    'fuzz-stream-token',
    sources: files('fuzz_stream_token.cpp'),
    include_directories: inc,
    cpp_args: fuzz_sanitizer_args,
    link_args: fuzz_sanitizer_args,
    link_with: [sync_lib, canonicaljson_lib],
  ),
  executable(
    'fuzz-query-params',
    sources: files('fuzz_query_params.cpp'),
    include_directories: inc,
    cpp_args: fuzz_sanitizer_args,
    link_args: fuzz_sanitizer_args,
    link_with: [core_lib],
  ),
  executable(
    'fuzz-srv-record',
    sources: files('fuzz_srv_record.cpp'),
    include_directories: inc,
    cpp_args: fuzz_sanitizer_args,
    link_args: fuzz_sanitizer_args,
    dependencies: [libsodium_dep, libcurl_dep, resolv_dep],
    link_with: [federation_lib, canonicaljson_lib, crypto_lib, database_lib, events_lib, http_lib, rooms_lib, observability_lib, platform_lib],
  ),
]
