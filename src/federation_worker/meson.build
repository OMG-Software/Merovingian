federation_worker_lib = static_library(
  'merovingian-federation-worker',
  sources: files(
    'args.cpp',
    'worker_event_loop.cpp',
  ),
  include_directories: [inc, include_directories('.')],
  dependencies: [thread_dep, libsodium_dep, openssl_dep, libpq_dep, sqlite_dep, libcurl_dep, resolv_dep],
  link_with: [
    auth_lib, canonicaljson_lib, core_lib, config_lib, crypto_lib,
    database_lib, events_lib, federation_lib, homeserver_lib, http_lib,
    ipc_lib, media_lib, net_lib, observability_lib, platform_lib,
    rooms_lib, sync_lib, trust_safety_lib,
  ],
)

federation_worker_exe = executable(
  'merovingian-fed-worker',
  sources: files(
    'main.cpp',
  ),
  include_directories: [inc, include_directories('.')],
  dependencies: [thread_dep, libsodium_dep, openssl_dep, libpq_dep, sqlite_dep, libcurl_dep, resolv_dep],
  link_with: [
    auth_lib, canonicaljson_lib, core_lib, config_lib, crypto_lib,
    database_lib, events_lib, federation_lib, homeserver_lib, http_lib,
    ipc_lib, media_lib, net_lib, observability_lib, platform_lib,
    rooms_lib, sync_lib, trust_safety_lib, federation_worker_lib,
  ],
  install: true,
  install_dir: get_option('libexecdir') / 'merovingian',
)
