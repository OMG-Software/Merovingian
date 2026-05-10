events_sources = files(
  'authorization.cpp',
  'event.cpp',
  'event_id.cpp',
  'event_signer.cpp',
  'redaction.cpp',
  'state_resolution.cpp',
)

events_lib = static_library(
  'merovingian-events',
  events_sources,
  include_directories: inc,
)
