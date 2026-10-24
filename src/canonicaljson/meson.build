canonicaljson_sources = files(
  'library_versions.cpp',
  'parser.cpp',
  'serializer.cpp',
  'signable.cpp',
  'value.cpp',
  'yyjson_adapter.c',
)

canonicaljson_lib = static_library(
  'merovingian-canonicaljson',
  canonicaljson_sources,
  include_directories: inc,
  dependencies: [yyjson_dep],
)
