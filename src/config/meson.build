config_sources = files(
  'Config.cpp',
  'ConfigParser.cpp',
  'ReloadPlan.cpp',
  'ReloadPolicy.cpp',
  'RuntimeConfigSnapshot.cpp',
)

config_lib = static_library(
  'merovingian-config',
  config_sources,
  include_directories: inc,
  # oauth_lib: validation reads server.public_baseurl and the hand-off allowlist with the OAuth readers.
  link_with: [auth_lib, email_lib, oauth_lib],
)
