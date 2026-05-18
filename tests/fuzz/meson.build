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
]
