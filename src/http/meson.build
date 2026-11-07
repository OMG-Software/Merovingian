http_sources = files(
  'client_address.cpp',
  'connection_guard.cpp',
  'ConnectionLimiter.cpp',
  'InFlightBudget.cpp',
  'keep_alive.cpp',
  'library_versions.cpp',
  'OutboundClient.cpp',
  'rate_limit.cpp',
  'request.cpp',
  'RequestLimits.cpp',
)

http_lib = static_library(
  'merovingian-http',
  http_sources,
  include_directories: inc,
  dependencies: [libcurl_dep],
  link_with: [core_lib],
)
