push_sources = files(
  'EmailDigestQueue.cpp',
  'GatewayCircuitBreaker.cpp',
  'GatewayInFlightLimiter.cpp',
  'PushBatchAdmission.cpp',
  'PushGatewayClient.cpp',
  'PushRetryQueue.cpp',
  'PushRules.cpp',
  'UserPushRules.cpp',
)

push_lib = static_library(
  'merovingian-push',
  push_sources,
  include_directories: inc,
)
