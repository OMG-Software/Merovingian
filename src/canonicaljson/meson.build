canonicaljson_sources = files(
  'LibraryVersions.cpp',
  'ObjectMember.cpp',
  'Parser.cpp',
  'Serializer.cpp',
  'Signable.cpp',
  'Value.cpp',
  'yyjson_adapter.c',
)

canonicaljson_lib = static_library(
  'merovingian-canonicaljson',
  canonicaljson_sources,
  include_directories: inc,
  dependencies: [yyjson_dep],
)
