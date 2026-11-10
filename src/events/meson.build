events_sources = files(
  'Authorization.cpp',
  'Event.cpp',
  'EventId.cpp',
  'EventSigner.cpp',
  'Redaction.cpp',
  'RedactionValidity.cpp',
  'StateResolution.cpp',
  'UnsignedData.cpp',
)

events_lib = static_library(
  'merovingian-events',
  events_sources,
  include_directories: inc,
  dependencies: [libsodium_dep],
  link_with: [auth_lib, canonicaljson_lib, crypto_lib, rooms_lib],
)
