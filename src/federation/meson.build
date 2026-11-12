federation_sources = files(
  'CachedServerDiscovery.cpp',
  'DeviceDisplayNames.cpp',
  'DispatchWorker.cpp',
  'EduIdempotenceWindow.cpp',
  'EventQuery.cpp',
  'InboundIngestion.cpp',
  'InboundRequest.cpp',
  'InviteRoomState.cpp',
  'KeyQuery.cpp',
  'RemoteDeviceList.cpp',
  'RemoteDeviceListCache.cpp',
  'KeySignatures.cpp',
  'MembershipEndpoints.cpp',
  'OutboundMembership.cpp',
  'OutboundTransactionSupport.cpp',
  'PublicRooms.cpp',
  'RemoteKeyCache.cpp',
  'RuntimeFederationConfig.cpp',
  'Security.cpp',
  'ServerAcl.cpp',
  'ServerAclGlob.cpp',
  'ServerDiscovery.cpp',
  'ThirdPartyInvite.cpp',
  'Transactions.cpp',
  'WorkerRelayBinding.cpp',
)

federation_lib = static_library(
  'merovingian-federation',
  federation_sources,
  include_directories: inc,
  dependencies: [libsodium_dep, libcurl_dep, resolv_dep],
  # config_lib: Security.cpp re-checks the private-range allowlist with
  # config::private_ip_range_is_allowable (ADR-0231).
  link_with: [canonicaljson_lib, config_lib, crypto_lib, database_lib, events_lib, http_lib, rooms_lib],
)
