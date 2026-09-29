http_sources = files(
  'client_address.cpp',
  'connection_guard.cpp',
  'connection_limiter.cpp',
  'keep_alive.cpp',
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
