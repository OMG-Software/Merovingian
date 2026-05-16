http_sources = files(
  'connection_guard.cpp',
  'outbound_client.cpp',
  'rate_limit.cpp',
  'request.cpp',
  'request_limits.cpp',
)

http_lib = static_library(
  'merovingian-http',
  http_sources,
  include_directories: inc,
  dependencies: [libcurl_dep],
)
