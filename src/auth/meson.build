auth_sources = files(
  'client_server_api.cpp',
  'identity.cpp',
  'key_api.cpp',
  'session.cpp',
  'token.cpp',
)

auth_lib = static_library(
  'merovingian-auth',
  auth_sources,
  include_directories: inc,
  link_with: [crypto_lib],
)
