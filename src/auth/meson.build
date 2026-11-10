auth_sources = files(
  'Argon2idAdmission.cpp',
  'Argon2idSlot.cpp',
  'FailureWindowTable.cpp',
  'Identity.cpp',
  'KeyApi.cpp',
  'OidcDiscovery.cpp',
  'Password.cpp',
  'Session.cpp',
  'Token.cpp',
)

auth_lib = static_library(
  'merovingian-auth',
  auth_sources,
  include_directories: inc,
  dependencies: [libsodium_dep],
  link_with: [crypto_lib, canonicaljson_lib],
)
