homeserver_sources = files(
  'auth_service.cpp',
  'client_server.cpp',
  'federation_proxy.cpp',
  'federation_request_routing.cpp',
  'http_server.cpp',
  'local_smoke_flow.cpp',
  'local_http_router.cpp',
  'local_services.cpp',
  'media_service.cpp',
  'room_service.cpp',
  'runtime.cpp',
  'space_hierarchy.cpp',
  'tls.cpp',
  'worker_pool.cpp',
  'worker_supervisor.cpp',
)

homeserver_lib = static_library(
  'merovingian-homeserver',
  homeserver_sources,
  include_directories: inc,
  dependencies: [libsodium_dep, openssl_dep],
)
