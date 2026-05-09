fuzz_targets = [
  executable(
    'fuzz-canonicaljson',
    sources: files('fuzz_canonicaljson.cpp'),
    include_directories: inc,
    link_with: [canonicaljson_lib],
  ),
  executable(
    'fuzz-http-request',
    sources: files('fuzz_http_request.cpp'),
    include_directories: inc,
    link_with: [http_lib],
  ),
]
