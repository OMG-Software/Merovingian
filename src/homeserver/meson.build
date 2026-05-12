homeserver_sources = files(
  'auth_service.cpp',
  'client_server.cpp',
  'http_server.cpp',
  'local_demo_flow.cpp',
  'local_http_router.cpp',
  'local_services.cpp',
  'media_service.cpp',
  'room_service.cpp',
  'runtime.cpp',
)

homeserver_lib = static_library(
  'merovingian-homeserver',
  homeserver_sources,
  include_directories: inc,
  dependencies: [libsodium_dep],
)
