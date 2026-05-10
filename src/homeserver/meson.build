homeserver_sources = files(
  'auth_service.cpp',
  'client_server_mvp.cpp',
  'local_http_router.cpp',
  'local_services.cpp',
  'room_service.cpp',
  'runtime.cpp',
  'vertical_slice.cpp',
)

homeserver_lib = static_library(
  'merovingian-homeserver',
  homeserver_sources,
  include_directories: inc,
)
