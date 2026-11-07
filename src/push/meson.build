push_sources = files(
  'EmailDigestQueue.cpp',
  'GatewayCircuitBreaker.cpp',
  'GatewayInFlightLimiter.cpp',
  'PushGatewayClient.cpp',
  'PushRetryQueue.cpp',
  'push_rules.cpp',
  'UserPushRules.cpp',
)

push_lib = static_library(
  'merovingian-push',
  push_sources,
  include_directories: inc,
)
