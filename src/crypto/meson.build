crypto_sources = files(
  'constant_time.cpp',
  'ed25519.cpp',
  'random.cpp',
  'signing_service.cpp',
)

crypto_lib = static_library(
  'merovingian-crypto',
  crypto_sources,
  include_directories: inc,
  dependencies: [libsodium_dep],
)
