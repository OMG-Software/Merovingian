crypto_sources = files(
  'ConstantTime.cpp',
  'Ed25519.cpp',
  'Encoding.cpp',
  'GenericHash.cpp',
  'HmacSha1.cpp',
  'IpcAuthKey.cpp',
  'IpcStreamCipher.cpp',
  'LibraryVersions.cpp',
  'MasterKey.cpp',
  'Random.cpp',
  'RefusingEd25519Provider.cpp',
  'RuntimeEd25519Provider.cpp',
  'RuntimeMultiKeyEd25519Provider.cpp',
  'SecretBox.cpp',
  'SigningService.cpp',
  'SigningKeyStore.cpp',
  'TokenKey.cpp',
)

crypto_lib = static_library(
  'merovingian-crypto',
  crypto_sources,
  include_directories: inc,
  dependencies: [libsodium_dep, openssl_dep],
)
