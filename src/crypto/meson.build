crypto_sources = files(
  'constant_time.cpp',
  'ed25519.cpp',
  'encoding.cpp',
  'generic_hash.cpp',
  'hmac_sha1.cpp',
  'IpcAuthKey.cpp',
  'IpcStreamCipher.cpp',
  'library_versions.cpp',
  'master_key.cpp',
  'random.cpp',
  'RefusingEd25519Provider.cpp',
  'RuntimeEd25519Provider.cpp',
  'RuntimeMultiKeyEd25519Provider.cpp',
  'secret_box.cpp',
  'signing_service.cpp',
  'SigningKeyStore.cpp',
  'token_key.cpp',
)

crypto_lib = static_library(
  'merovingian-crypto',
  crypto_sources,
  include_directories: inc,
  dependencies: [libsodium_dep, openssl_dep],
)
