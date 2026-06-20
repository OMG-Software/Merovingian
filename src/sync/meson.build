sync_sources = files(
  'sliding_sync_extensions.cpp',
  'sliding_sync_parser.cpp',
  'sliding_sync_room_builder.cpp',
  'sliding_sync_room_list.cpp',
  'stream_token.cpp',
  'sync_filter.cpp',
  'sync_notifier.cpp',
)

sync_lib = static_library(
  'merovingian-sync',
  sync_sources,
  include_directories: inc,
  link_with: [canonicaljson_lib, database_lib],
)