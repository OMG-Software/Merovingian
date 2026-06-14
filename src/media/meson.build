media_sources = files(
  'repository.cpp',
  'runtime_media.cpp',
  'security.cpp',
  'thumbnailer.cpp',
)

# Default install location of the out-of-process thumbnail worker. The runtime
# uses this when the operator does not override it in config; tests and the
# build tree pass an explicit path instead.
thumbnail_worker_install_path = get_option('prefix') / get_option('libexecdir') / 'merovingian' / 'merovingian-thumbnail-worker'

media_lib = static_library(
  'merovingian-media',
  media_sources,
  include_directories: inc,
  dependencies: [libsodium_dep],
  cpp_args: ['-DMEROVINGIAN_THUMBNAIL_WORKER_PATH="' + thumbnail_worker_install_path + '"'],
)
