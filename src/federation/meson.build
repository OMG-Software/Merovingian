federation_sources = files(
  'CachedServerDiscovery.cpp',
  'DeviceDisplayNames.cpp',
  'DispatchWorker.cpp',
  'EduIdempotenceWindow.cpp',
  'event_query.cpp',
  'inbound_ingestion.cpp',
  'inbound_request.cpp',
  'invite_room_state.cpp',
  'key_query.cpp',
  'key_signatures.cpp',
  'membership_endpoints.cpp',
  'outbound_membership.cpp',
  'outbound_transaction.cpp',
  'public_rooms.cpp',
  'remote_key_cache.cpp',
  'RuntimeFederationConfig.cpp',
  'security.cpp',
  'server_acl.cpp',
  'server_discovery.cpp',
  'third_party_invite.cpp',
  'transactions.cpp',
)

federation_lib = static_library(
  'merovingian-federation',
  federation_sources,
  include_directories: inc,
  dependencies: [libsodium_dep, libcurl_dep, resolv_dep],
  # config_lib: security.cpp re-checks the private-range allowlist with
  # config::private_ip_range_is_allowable (ADR-0231).
  link_with: [canonicaljson_lib, config_lib, crypto_lib, database_lib, events_lib, http_lib, rooms_lib],
)
