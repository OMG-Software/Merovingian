sync_sources = files(
  'stream_token.cpp',
  'sync_filter.cpp',
  'sync_notifier.cpp',
)

sync_lib = static_library(
  'merovingian-sync',
  sync_sources,
  include_directories: inc,
  link_with: [canonicaljson_lib],
)