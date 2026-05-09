subdir('auth')
subdir('canonicaljson')
subdir('core')
subdir('config')
subdir('database')
subdir('events')
subdir('federation')
subdir('http')
subdir('media')
subdir('net')
subdir('platform')
subdir('rooms')

executable(
  'merovingian-server',
  sources: files('main.cpp'),
  include_directories: inc,
  dependencies: [thread_dep],
  link_with: [auth_lib, canonicaljson_lib, core_lib, config_lib, database_lib, events_lib, federation_lib, http_lib, media_lib, net_lib, platform_lib, rooms_lib],
  install: true,
)
