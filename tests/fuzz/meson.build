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
    link_with: [config_lib, http_lib, observability_lib, core_lib, platform_lib],
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

# Targets that reach the parsers behind the homeserver, federation and ipc modules. Those modules
# depend on most of the others, so they link the same libraries merovingian-server does.
fuzz_server_libs = [
  appservice_lib, auth_lib, canonicaljson_lib, core_lib, config_lib, crypto_lib, database_lib, email_lib,
  events_lib, federation_lib, homeserver_lib, http_lib, identity_lib, ipc_lib, media_lib, net_lib,
  observability_lib, platform_lib, push_lib, rooms_lib, sync_lib, trust_safety_lib,
]
fuzz_server_deps = [thread_dep, libsodium_dep, openssl_dep, libpq_dep, sqlite_dep, libcurl_dep, resolv_dep]

foreach target : [
  ['fuzz-multipart-upload', 'fuzz_multipart_upload.cpp'],
  ['fuzz-url-preview-html', 'fuzz_url_preview_html.cpp'],
  ['fuzz-x-matrix-header', 'fuzz_x_matrix_header.cpp'],
  ['fuzz-inbound-pdu', 'fuzz_inbound_pdu.cpp'],
  ['fuzz-ipc-frame', 'fuzz_ipc_frame.cpp'],
  ['fuzz-appservice-yaml', 'fuzz_appservice_yaml.cpp'],
  ['fuzz-push-glob', 'fuzz_push_glob.cpp'],
]
  fuzz_targets += executable(
    target[0],
    sources: files(target[1]),
    include_directories: [inc, include_directories('.')],
    cpp_args: fuzz_sanitizer_args,
    link_args: fuzz_sanitizer_args,
    dependencies: fuzz_server_deps,
    link_with: fuzz_server_libs,
  )
endforeach
