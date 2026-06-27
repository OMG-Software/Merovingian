subdir('crypto')
subdir('auth')
subdir('canonicaljson')
subdir('core')
subdir('config')
subdir('database')
subdir('rooms')
subdir('events')
subdir('http')
subdir('federation')
subdir('ipc')
subdir('homeserver')
subdir('media')
subdir('net')
subdir('observability')
subdir('platform')
subdir('sync')
subdir('trust_safety')

subdir('federation_worker')

executable(
  'merovingian-server',
  sources: files('main.cpp'),
  include_directories: inc,
  dependencies: [thread_dep, libsodium_dep, openssl_dep, libpq_dep, sqlite_dep, libcurl_dep, resolv_dep],
  link_with: [auth_lib, canonicaljson_lib, core_lib, config_lib, crypto_lib, database_lib, events_lib, federation_lib, homeserver_lib, http_lib, ipc_lib, media_lib, net_lib, observability_lib, platform_lib, rooms_lib, sync_lib, trust_safety_lib],
  install: true,
)

executable(
  'merovingian-db-migrate',
  sources: files('db_migrate.cpp'),
  include_directories: inc,
  dependencies: [thread_dep, libpq_dep, sqlite_dep],
  link_with: [config_lib, canonicaljson_lib, database_lib, observability_lib, platform_lib],
  install: true,
)

# Out-of-process, sandboxed image thumbnail worker. Built only when the system
# image codecs are available; when they are not, the server degrades gracefully
# (thumbnail requests fall back to serving the original media bytes).
libpng_dep = dependency('libpng16', required: false)
turbojpeg_dep = dependency('libturbojpeg', required: false)
thumbnail_worker_available = libpng_dep.found() and turbojpeg_dep.found()
thumbnail_worker_exe = []
if thumbnail_worker_available
  thumbnail_worker_exe = executable(
    'merovingian-thumbnail-worker',
    sources: files('media/thumbnailer.cpp', 'media/thumbnail_worker_main.cpp'),
    include_directories: inc,
    dependencies: [libpng_dep, turbojpeg_dep],
    link_with: [core_lib, platform_lib],
    install: true,
    install_dir: get_option('libexecdir') / 'merovingian',
  )
endif
