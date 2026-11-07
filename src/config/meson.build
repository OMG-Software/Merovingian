config_sources = files(
  'Config.cpp',
  'config_parser.cpp',
  'ReloadPlan.cpp',
  'ReloadPolicy.cpp',
  'RuntimeConfigSnapshot.cpp',
)

config_lib = static_library(
  'merovingian-config',
  config_sources,
  include_directories: inc,
  link_with: [auth_lib, email_lib],
)
