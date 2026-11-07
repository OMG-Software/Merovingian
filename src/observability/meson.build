observability_sources = files(
  'audit_rate_gate.cpp',
  'bounded_text.cpp',
  'CorrelationScope.cpp',
  'observability.cpp',
)

observability_lib = static_library(
  'merovingian-observability',
  observability_sources,
  include_directories: inc,
)
