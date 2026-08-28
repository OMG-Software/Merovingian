homeserver_sources = files(
  'auth_service.cpp',
  'client_server.cpp',
  'default_push_ruleset.cpp',
  'federation_proxy.cpp',
  'federation_request_routing.cpp',
  'http_server.cpp',
  'local_smoke_flow.cpp',
  'local_http_router.cpp',
  'local_services.cpp',
  'media_service.cpp',
  'request_lock.cpp',
  'room_service.cpp',
  'runtime.cpp',
  'runtime_signing_key_store.cpp',
  'space_hierarchy.cpp',
  'tls.cpp',
  'worker_env.cpp',
  'worker_pool.cpp',
  'worker_supervisor.cpp',
)

homeserver_lib = static_library(
  'merovingian-homeserver',
  homeserver_sources,
  include_directories: inc,
  dependencies: [libsodium_dep, openssl_dep],
)
