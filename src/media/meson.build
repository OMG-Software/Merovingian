media_sources = files(
  'repository.cpp',
  'runtime_media.cpp',
  'security.cpp',
)

media_lib = static_library(
  'merovingian-media',
  media_sources,
  include_directories: inc,
  dependencies: [libsodium_dep],
)
