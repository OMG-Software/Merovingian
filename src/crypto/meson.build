crypto_sources = files(
  'constant_time.cpp',
  'ed25519.cpp',
  'ipc_auth_key.cpp',
  'master_key.cpp',
  'random.cpp',
  'secret_box.cpp',
  'signing_service.cpp',
  'token_key.cpp',
)

crypto_lib = static_library(
  'merovingian-crypto',
  crypto_sources,
  include_directories: inc,
  dependencies: [libsodium_dep],
)
