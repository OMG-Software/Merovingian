federation_sources = files(
  'dispatch_worker.cpp',
  'event_query.cpp',
  'inbound_ingestion.cpp',
  'inbound_request.cpp',
  'key_query.cpp',
  'membership_endpoints.cpp',
  'outbound_membership.cpp',
  'outbound_transaction.cpp',
  'remote_key_cache.cpp',
  'runtime_federation.cpp',
  'security.cpp',
  'server_discovery.cpp',
  'transactions.cpp',
)

federation_lib = static_library(
  'merovingian-federation',
  federation_sources,
  include_directories: inc,
  dependencies: [libsodium_dep, libcurl_dep, resolv_dep],
  link_with: [canonicaljson_lib, crypto_lib, database_lib, events_lib, http_lib, rooms_lib],
)
