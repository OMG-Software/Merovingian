auth_sources = files(
  'failure_window_table.cpp',
  'identity.cpp',
  'key_api.cpp',
  'oidc_discovery.cpp',
  'password.cpp',
  'session.cpp',
  'token.cpp',
)

auth_lib = static_library(
  'merovingian-auth',
  auth_sources,
  include_directories: inc,
  dependencies: [libsodium_dep],
  link_with: [crypto_lib, canonicaljson_lib],
)
