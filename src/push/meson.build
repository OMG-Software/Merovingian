push_sources = files(
  'email_digest_queue.cpp',
  'gateway_circuit_breaker.cpp',
  'push_gateway_client.cpp',
  'push_retry_queue.cpp',
  'push_rules.cpp',
  'user_push_rules.cpp',
)

push_lib = static_library(
  'merovingian-push',
  push_sources,
  include_directories: inc,
)
