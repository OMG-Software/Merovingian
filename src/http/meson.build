http_sources = files(
  'ClientAddress.cpp',
  'ConnectionGuard.cpp',
  'ConnectionLimiter.cpp',
  'InFlightBudget.cpp',
  'KeepAlive.cpp',
  'LibraryVersions.cpp',
  'OutboundClient.cpp',
  'RateLimit.cpp',
  'Request.cpp',
  'RequestLimits.cpp',
)

http_lib = static_library(
  'merovingian-http',
  http_sources,
  include_directories: inc,
  dependencies: [libcurl_dep],
  link_with: [core_lib],
)
