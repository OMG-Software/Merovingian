subdir('auth')
subdir('canonicaljson')
subdir('core')
subdir('config')
subdir('crypto')
subdir('database')
subdir('rooms')
subdir('events')
subdir('http')
subdir('federation')
subdir('homeserver')
subdir('media')
subdir('net')
subdir('observability')
subdir('platform')
subdir('sync')
subdir('trust_safety')

executable(
  'merovingian-server',
  sources: files('main.cpp'),
  include_directories: inc,
  dependencies: [thread_dep, libsodium_dep, openssl_dep, libpq_dep, sqlite_dep, libcurl_dep, resolv_dep],
  link_with: [auth_lib, canonicaljson_lib, core_lib, config_lib, crypto_lib, database_lib, events_lib, federation_lib, homeserver_lib, http_lib, media_lib, net_lib, observability_lib, platform_lib, rooms_lib, sync_lib, trust_safety_lib],
  install: true,
)

executable(
  'merovingian-db-migrate',
  sources: files('db_migrate.cpp'),
  include_directories: inc,
  dependencies: [thread_dep, libpq_dep, sqlite_dep],
  link_with: [config_lib, database_lib, observability_lib],
  install: true,
)
