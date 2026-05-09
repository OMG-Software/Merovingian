subdir('core')
subdir('config')
subdir('database')
subdir('federation')
subdir('media')
subdir('net')
subdir('platform')

executable(
  'merovingian-server',
  sources: files('main.cpp'),
  include_directories: inc,
  dependencies: [thread_dep],
  link_with: [core_lib, config_lib, database_lib, federation_lib, media_lib, net_lib, platform_lib],
  install: true,
)
