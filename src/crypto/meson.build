crypto_sources = files(
  'constant_time.cpp',
  'ed25519.cpp',
  'encoding.cpp',
  'generic_hash.cpp',
  'ipc_auth_key.cpp',
  'ipc_stream_cipher.cpp',
  'master_key.cpp',
  'random.cpp',
  'runtime_ed25519_provider.cpp',
  'runtime_multikey_ed25519_provider.cpp',
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
